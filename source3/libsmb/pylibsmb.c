/*
 * Unix SMB/CIFS implementation.
 * Samba-internal work in progress Python binding for libsmbclient
 *
 * Copyright (C) Volker Lendecke 2012
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include "includes.h"
#include "python/py3compat.h"
#include "libcli/smb/smbXcli_base.h"
#include "libsmb/libsmb.h"
#include "libcli/security/security.h"
#include "system/select.h"
#include "source4/libcli/util/pyerrors.h"
#include "auth/credentials/pycredentials.h"
#include "trans2.h"

static PyTypeObject *get_pytype(const char *module, const char *type)
{
	PyObject *mod;
	PyTypeObject *result;

	mod = PyImport_ImportModule(module);
	if (mod == NULL) {
		PyErr_Format(PyExc_RuntimeError,
			     "Unable to import %s to check type %s",
			     module, type);
		return NULL;
	}
	result = (PyTypeObject *)PyObject_GetAttrString(mod, type);
	Py_DECREF(mod);
	if (result == NULL) {
		PyErr_Format(PyExc_RuntimeError,
			     "Unable to find type %s in module %s",
			     module, type);
		return NULL;
	}
	return result;
}

/*
 * We're using "const char * const *" for keywords,
 * PyArg_ParseTupleAndKeywords expects a "char **". Confine the
 * inevitable warnings to just one place.
 */
static int ParseTupleAndKeywords(PyObject *args, PyObject *kw,
				 const char *format, const char * const *keywords,
				 ...)
{
	char **_keywords = discard_const_p(char *, keywords);
	va_list a;
	int ret;
	va_start(a, keywords);
	ret = PyArg_VaParseTupleAndKeywords(args, kw, format,
					    _keywords, a);
	va_end(a);
	return ret;
}

struct py_cli_thread;

struct py_cli_oplock_break {
	uint16_t fnum;
	uint8_t level;
};

struct py_cli_state {
	PyObject_HEAD
	struct cli_state *cli;
	bool is_smb1;
	struct tevent_context *ev;
	int (*req_wait_fn)(struct tevent_context *ev,
			   struct tevent_req *req);
	struct py_cli_thread *thread_state;

	struct tevent_req *oplock_waiter;
	struct py_cli_oplock_break *oplock_breaks;
	struct py_tevent_cond *oplock_cond;
};

#ifdef HAVE_PTHREAD

#include <pthread.h>

struct py_cli_thread {

	/*
	 * Pipe to make the poll thread wake up in our destructor, so
	 * that we can exit and join the thread.
	 */
	int shutdown_pipe[2];
	struct tevent_fd *shutdown_fde;
	bool do_shutdown;
	pthread_t id;

	/*
	 * Thread state to release the GIL during the poll(2) syscall
	 */
	PyThreadState *py_threadstate;
};

static void *py_cli_state_poll_thread(void *private_data)
{
	struct py_cli_state *self = (struct py_cli_state *)private_data;
	struct py_cli_thread *t = self->thread_state;
	PyGILState_STATE gstate;

	gstate = PyGILState_Ensure();

	while (!t->do_shutdown) {
		int ret;
		ret = tevent_loop_once(self->ev);
		assert(ret == 0);
	}
	PyGILState_Release(gstate);
	return NULL;
}

static void py_cli_state_trace_callback(enum tevent_trace_point point,
					void *private_data)
{
	struct py_cli_state *self = (struct py_cli_state *)private_data;
	struct py_cli_thread *t = self->thread_state;

	switch(point) {
	case TEVENT_TRACE_BEFORE_WAIT:
		assert(t->py_threadstate == NULL);
		t->py_threadstate = PyEval_SaveThread();
		break;
	case TEVENT_TRACE_AFTER_WAIT:
		assert(t->py_threadstate != NULL);
		PyEval_RestoreThread(t->py_threadstate);
		t->py_threadstate = NULL;
		break;
	default:
		break;
	}
}

static void py_cli_state_shutdown_handler(struct tevent_context *ev,
					  struct tevent_fd *fde,
					  uint16_t flags,
					  void *private_data)
{
	struct py_cli_state *self = (struct py_cli_state *)private_data;
	struct py_cli_thread *t = self->thread_state;

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}
	TALLOC_FREE(t->shutdown_fde);
	t->do_shutdown = true;
}

static int py_cli_thread_destructor(struct py_cli_thread *t)
{
	char c = 0;
	ssize_t written;
	int ret;

	do {
		/*
		 * This will wake the poll thread from the poll(2)
		 */
		written = write(t->shutdown_pipe[1], &c, 1);
	} while ((written == -1) && (errno == EINTR));

	/*
	 * Allow the poll thread to do its own cleanup under the GIL
	 */
	Py_BEGIN_ALLOW_THREADS
	ret = pthread_join(t->id, NULL);
	Py_END_ALLOW_THREADS
	assert(ret == 0);

	if (t->shutdown_pipe[0] != -1) {
		close(t->shutdown_pipe[0]);
		t->shutdown_pipe[0] = -1;
	}
	if (t->shutdown_pipe[1] != -1) {
		close(t->shutdown_pipe[1]);
		t->shutdown_pipe[1] = -1;
	}
	return 0;
}

static int py_tevent_cond_req_wait(struct tevent_context *ev,
				   struct tevent_req *req);

static bool py_cli_state_setup_mt_ev(struct py_cli_state *self)
{
	struct py_cli_thread *t = NULL;
	int ret;

	self->ev = tevent_context_init_byname(NULL, "poll_mt");
	if (self->ev == NULL) {
		goto fail;
	}
	samba_tevent_set_debug(self->ev, "pylibsmb_tevent_mt");
	tevent_set_trace_callback(self->ev, py_cli_state_trace_callback, self);

	self->req_wait_fn = py_tevent_cond_req_wait;

	self->thread_state = talloc_zero(NULL, struct py_cli_thread);
	if (self->thread_state == NULL) {
		goto fail;
	}
	t = self->thread_state;

	ret = pipe(t->shutdown_pipe);
	if (ret == -1) {
		goto fail;
	}
	t->shutdown_fde = tevent_add_fd(
		self->ev, self->ev, t->shutdown_pipe[0], TEVENT_FD_READ,
		py_cli_state_shutdown_handler, self);
	if (t->shutdown_fde == NULL) {
		goto fail;
	}

	PyEval_InitThreads();

	ret = pthread_create(&t->id, NULL, py_cli_state_poll_thread, self);
	if (ret != 0) {
		goto fail;
	}
	talloc_set_destructor(self->thread_state, py_cli_thread_destructor);
	return true;

fail:
	if (t != NULL) {
		TALLOC_FREE(t->shutdown_fde);

		if (t->shutdown_pipe[0] != -1) {
			close(t->shutdown_pipe[0]);
			t->shutdown_pipe[0] = -1;
		}
		if (t->shutdown_pipe[1] != -1) {
			close(t->shutdown_pipe[1]);
			t->shutdown_pipe[1] = -1;
		}
	}

	TALLOC_FREE(self->thread_state);
	TALLOC_FREE(self->ev);
	return false;
}

struct py_tevent_cond {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool is_done;
};

static void py_tevent_signalme(struct tevent_req *req);

static int py_tevent_cond_wait(struct py_tevent_cond *cond)
{
	int ret, result;

	result = pthread_mutex_init(&cond->mutex, NULL);
	if (result != 0) {
		goto fail;
	}
	result = pthread_cond_init(&cond->cond, NULL);
	if (result != 0) {
		goto fail_mutex;
	}

	result = pthread_mutex_lock(&cond->mutex);
	if (result != 0) {
		goto fail_cond;
	}

	cond->is_done = false;

	while (!cond->is_done) {

		Py_BEGIN_ALLOW_THREADS
		result = pthread_cond_wait(&cond->cond, &cond->mutex);
		Py_END_ALLOW_THREADS

		if (result != 0) {
			goto fail_unlock;
		}
	}

fail_unlock:
	ret = pthread_mutex_unlock(&cond->mutex);
	assert(ret == 0);
fail_cond:
	ret = pthread_cond_destroy(&cond->cond);
	assert(ret == 0);
fail_mutex:
	ret = pthread_mutex_destroy(&cond->mutex);
	assert(ret == 0);
fail:
	return result;
}

static int py_tevent_cond_req_wait(struct tevent_context *ev,
				   struct tevent_req *req)
{
	struct py_tevent_cond cond;
	tevent_req_set_callback(req, py_tevent_signalme, &cond);
	return py_tevent_cond_wait(&cond);
}

static void py_tevent_cond_signal(struct py_tevent_cond *cond)
{
	int ret;

	ret = pthread_mutex_lock(&cond->mutex);
	assert(ret == 0);

	cond->is_done = true;

	ret = pthread_cond_signal(&cond->cond);
	assert(ret == 0);
	ret = pthread_mutex_unlock(&cond->mutex);
	assert(ret == 0);
}

static void py_tevent_signalme(struct tevent_req *req)
{
	struct py_tevent_cond *cond = (struct py_tevent_cond *)
		tevent_req_callback_data_void(req);

	py_tevent_cond_signal(cond);
}

#endif

static int py_tevent_req_wait(struct tevent_context *ev,
			      struct tevent_req *req);

static bool py_cli_state_setup_ev(struct py_cli_state *self)
{
	self->ev = tevent_context_init(NULL);
	if (self->ev == NULL) {
		return false;
	}

	samba_tevent_set_debug(self->ev, "pylibsmb_tevent");

	self->req_wait_fn = py_tevent_req_wait;

	return true;
}

static int py_tevent_req_wait(struct tevent_context *ev,
			      struct tevent_req *req)
{
	while (tevent_req_is_in_progress(req)) {
		int ret;

		ret = tevent_loop_once(ev);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static bool py_tevent_req_wait_exc(struct py_cli_state *self,
				   struct tevent_req *req)
{
	int ret;

	if (req == NULL) {
		PyErr_NoMemory();
		return false;
	}
	ret = self->req_wait_fn(self->ev, req);
	if (ret != 0) {
		TALLOC_FREE(req);
		errno = ret;
		PyErr_SetFromErrno(PyExc_RuntimeError);
		return false;
	}
	return true;
}

static PyObject *py_cli_state_new(PyTypeObject *type, PyObject *args,
				  PyObject *kwds)
{
	struct py_cli_state *self;

	self = (struct py_cli_state *)type->tp_alloc(type, 0);
	if (self == NULL) {
		return NULL;
	}
	self->cli = NULL;
	self->is_smb1 = false;
	self->ev = NULL;
	self->thread_state = NULL;
	self->oplock_waiter = NULL;
	self->oplock_cond = NULL;
	self->oplock_breaks = NULL;
	return (PyObject *)self;
}

static void py_cli_got_oplock_break(struct tevent_req *req);

static int py_cli_state_init(struct py_cli_state *self, PyObject *args,
			     PyObject *kwds)
{
	NTSTATUS status;
	char *host, *share;
	PyObject *creds = NULL;
	struct cli_credentials *cli_creds;
	PyObject *py_multi_threaded = Py_False;
	bool multi_threaded = false;
	PyObject *py_sign = Py_False;
	bool sign = false;
	int signing_state = SMB_SIGNING_DEFAULT;
	PyObject *py_force_smb1 = Py_False;
	bool force_smb1 = false;
	struct tevent_req *req;
	bool ret;
	int flags = 0;

	static const char *kwlist[] = {
		"host", "share", "credentials",
		"multi_threaded", "sign", "force_smb1",
		NULL
	};

	PyTypeObject *py_type_Credentials = get_pytype(
		"samba.credentials", "Credentials");
	if (py_type_Credentials == NULL) {
		return -1;
	}

	ret = ParseTupleAndKeywords(
		args, kwds, "ss|O!OOO", kwlist,
		&host, &share,
		py_type_Credentials, &creds,
		&py_multi_threaded,
		&py_sign,
		&py_force_smb1);

	Py_DECREF(py_type_Credentials);

	if (!ret) {
		return -1;
	}

	multi_threaded = PyObject_IsTrue(py_multi_threaded);
	sign = PyObject_IsTrue(py_sign);
	force_smb1 = PyObject_IsTrue(py_force_smb1);

	if (sign) {
		signing_state = SMB_SIGNING_REQUIRED;
	}

	if (force_smb1) {
		/*
		 * As most of the cli_*_send() function
		 * don't support SMB2 (it's only plugged
		 * into the sync wrapper functions currently)
		 * we have a way to force SMB1.
		 */
		flags = CLI_FULL_CONNECTION_FORCE_SMB1;
	}

	if (multi_threaded) {
#ifdef HAVE_PTHREAD
		ret = py_cli_state_setup_mt_ev(self);
		if (!ret) {
			return -1;
		}
#else
		PyErr_SetString(PyExc_RuntimeError,
				"No PTHREAD support available");
		return -1;
#endif
		if (!force_smb1) {
			PyErr_SetString(PyExc_RuntimeError,
					"multi_threaded is only possible on "
					"SMB1 connections");
			return -1;
		}
	} else {
		ret = py_cli_state_setup_ev(self);
		if (!ret) {
			return -1;
		}
	}

	if (creds == NULL) {
		cli_creds = cli_credentials_init_anon(NULL);
	} else {
		cli_creds = PyCredentials_AsCliCredentials(creds);
	}

	req = cli_full_connection_creds_send(
		NULL, self->ev, "myname", host, NULL, 0, share, "?????",
		cli_creds, flags, signing_state);
	if (!py_tevent_req_wait_exc(self, req)) {
		return -1;
	}
	status = cli_full_connection_creds_recv(req, &self->cli);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return -1;
	}

	if (smbXcli_conn_protocol(self->cli->conn) < PROTOCOL_SMB2_02) {
		self->is_smb1 = true;
	}

	/*
	 * Oplocks require a multi threaded connection
	 */
	if (self->thread_state == NULL) {
		return 0;
	}

	self->oplock_waiter = cli_smb_oplock_break_waiter_send(
		self->ev, self->ev, self->cli);
	if (self->oplock_waiter == NULL) {
		PyErr_NoMemory();
		return -1;
	}
	tevent_req_set_callback(self->oplock_waiter, py_cli_got_oplock_break,
				self);
	return 0;
}

static void py_cli_got_oplock_break(struct tevent_req *req)
{
	struct py_cli_state *self = (struct py_cli_state *)
		tevent_req_callback_data_void(req);
	struct py_cli_oplock_break b;
	struct py_cli_oplock_break *tmp;
	size_t num_breaks;
	NTSTATUS status;

	status = cli_smb_oplock_break_waiter_recv(req, &b.fnum, &b.level);
	TALLOC_FREE(req);
	self->oplock_waiter = NULL;

	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	num_breaks = talloc_array_length(self->oplock_breaks);
	tmp = talloc_realloc(self->ev, self->oplock_breaks,
			     struct py_cli_oplock_break, num_breaks+1);
	if (tmp == NULL) {
		return;
	}
	self->oplock_breaks = tmp;
	self->oplock_breaks[num_breaks] = b;

	if (self->oplock_cond != NULL) {
		py_tevent_cond_signal(self->oplock_cond);
	}

	self->oplock_waiter = cli_smb_oplock_break_waiter_send(
		self->ev, self->ev, self->cli);
	if (self->oplock_waiter == NULL) {
		return;
	}
	tevent_req_set_callback(self->oplock_waiter, py_cli_got_oplock_break,
				self);
}

static PyObject *py_cli_get_oplock_break(struct py_cli_state *self,
					 PyObject *args)
{
	size_t num_oplock_breaks;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

	if (self->thread_state == NULL) {
		PyErr_SetString(PyExc_RuntimeError,
				"get_oplock_break() only possible on "
				"a multi_threaded connection");
		return NULL;
	}

	if (self->oplock_cond != NULL) {
		errno = EBUSY;
		PyErr_SetFromErrno(PyExc_RuntimeError);
		return NULL;
	}

	num_oplock_breaks = talloc_array_length(self->oplock_breaks);

	if (num_oplock_breaks == 0) {
		struct py_tevent_cond cond;
		int ret;

		self->oplock_cond = &cond;
		ret = py_tevent_cond_wait(&cond);
		self->oplock_cond = NULL;

		if (ret != 0) {
			errno = ret;
			PyErr_SetFromErrno(PyExc_RuntimeError);
			return NULL;
		}
	}

	num_oplock_breaks = talloc_array_length(self->oplock_breaks);
	if (num_oplock_breaks > 0) {
		PyObject *result;

		result = Py_BuildValue(
			"{s:i,s:i}",
			"fnum", self->oplock_breaks[0].fnum,
			"level", self->oplock_breaks[0].level);

		memmove(&self->oplock_breaks[0], &self->oplock_breaks[1],
			sizeof(self->oplock_breaks[0]) *
			(num_oplock_breaks - 1));
		self->oplock_breaks = talloc_realloc(
			NULL, self->oplock_breaks, struct py_cli_oplock_break,
			num_oplock_breaks - 1);

		return result;
	}
	Py_RETURN_NONE;
}

static void py_cli_state_dealloc(struct py_cli_state *self)
{
	TALLOC_FREE(self->thread_state);
	TALLOC_FREE(self->oplock_waiter);
	TALLOC_FREE(self->ev);

	if (self->cli != NULL) {
		cli_shutdown(self->cli);
		self->cli = NULL;
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *py_cli_settimeout(struct py_cli_state *self, PyObject *args)
{
	unsigned int nmsecs = 0;
	unsigned int omsecs = 0;

	if (!PyArg_ParseTuple(args, "I", &nmsecs)) {
		return NULL;
	}

	omsecs = cli_set_timeout(self->cli, nmsecs);

	return PyInt_FromLong(omsecs);
}

static PyObject *py_cli_create(struct py_cli_state *self, PyObject *args,
			       PyObject *kwds)
{
	char *fname;
	unsigned CreateFlags = 0;
	unsigned DesiredAccess = FILE_GENERIC_READ;
	unsigned FileAttributes = 0;
	unsigned ShareAccess = 0;
	unsigned CreateDisposition = FILE_OPEN;
	unsigned CreateOptions = 0;
	unsigned ImpersonationLevel = SMB2_IMPERSONATION_IMPERSONATION;
	unsigned SecurityFlags = 0;
	uint16_t fnum;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"Name", "CreateFlags", "DesiredAccess", "FileAttributes",
		"ShareAccess", "CreateDisposition", "CreateOptions",
		"ImpersonationLevel", "SecurityFlags", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "s|IIIIIIII", kwlist,
		    &fname, &CreateFlags, &DesiredAccess, &FileAttributes,
		    &ShareAccess, &CreateDisposition, &CreateOptions,
		    &ImpersonationLevel, &SecurityFlags)) {
		return NULL;
	}

	req = cli_ntcreate_send(NULL, self->ev, self->cli, fname, CreateFlags,
				DesiredAccess, FileAttributes, ShareAccess,
				CreateDisposition, CreateOptions,
				ImpersonationLevel, SecurityFlags);
	if (!py_tevent_req_wait_exc(self, req)) {
		return NULL;
	}
	status = cli_ntcreate_recv(req, &fnum, NULL);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	return Py_BuildValue("I", (unsigned)fnum);
}

static PyObject *py_cli_close(struct py_cli_state *self, PyObject *args)
{
	struct tevent_req *req;
	int fnum;
	NTSTATUS status;

	if (!PyArg_ParseTuple(args, "i", &fnum)) {
		return NULL;
	}

	req = cli_close_send(NULL, self->ev, self->cli, fnum);
	if (!py_tevent_req_wait_exc(self, req)) {
		return NULL;
	}
	status = cli_close_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_cli_write(struct py_cli_state *self, PyObject *args,
			      PyObject *kwds)
{
	int fnum;
	unsigned mode = 0;
	char *buf;
	Py_ssize_t buflen;
	unsigned long long offset;
	struct tevent_req *req;
	NTSTATUS status;
	size_t written;

	static const char *kwlist[] = {
		"fnum", "buffer", "offset", "mode", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "I" PYARG_BYTES_LEN "K|I", kwlist,
		    &fnum, &buf, &buflen, &offset, &mode)) {
		return NULL;
	}

	req = cli_write_send(NULL, self->ev, self->cli, fnum, mode,
			     (uint8_t *)buf, offset, buflen);
	if (!py_tevent_req_wait_exc(self, req)) {
		return NULL;
	}
	status = cli_write_recv(req, &written);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	return Py_BuildValue("K", (unsigned long long)written);
}

static PyObject *py_cli_read(struct py_cli_state *self, PyObject *args,
			     PyObject *kwds)
{
	int fnum;
	unsigned long long offset;
	unsigned size;
	struct tevent_req *req;
	NTSTATUS status;
	char *buf;
	size_t received;
	PyObject *result;

	static const char *kwlist[] = {
		"fnum", "offset", "size", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "IKI", kwlist, &fnum, &offset,
		    &size)) {
		return NULL;
	}

	result = PyBytes_FromStringAndSize(NULL, size);
	if (result == NULL) {
		return NULL;
	}
	buf = PyBytes_AS_STRING(result);

	req = cli_read_send(NULL, self->ev, self->cli, fnum,
			    buf, offset, size);
	if (!py_tevent_req_wait_exc(self, req)) {
		Py_XDECREF(result);
		return NULL;
	}
	status = cli_read_recv(req, &received);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		Py_XDECREF(result);
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	if (received > size) {
		Py_XDECREF(result);
		PyErr_Format(PyExc_IOError,
			     "read invalid - got %zu requested %u",
			     received, size);
		return NULL;
	}

	if (received < size) {
		if (_PyBytes_Resize(&result, received) < 0) {
			return NULL;
		}
	}

	return result;
}

static PyObject *py_cli_ftruncate(struct py_cli_state *self, PyObject *args,
				  PyObject *kwds)
{
	int fnum;
	unsigned long long size;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"fnum", "size", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "IK", kwlist, &fnum, &size)) {
		return NULL;
	}

	req = cli_ftruncate_send(NULL, self->ev, self->cli, fnum, size);
	if (!py_tevent_req_wait_exc(self, req)) {
		return NULL;
	}
	status = cli_ftruncate_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_cli_delete_on_close(struct py_cli_state *self,
					PyObject *args,
					PyObject *kwds)
{
	unsigned fnum, flag;
	struct tevent_req *req;
	NTSTATUS status;

	static const char *kwlist[] = {
		"fnum", "flag", NULL };

	if (!ParseTupleAndKeywords(
		    args, kwds, "II", kwlist, &fnum, &flag)) {
		return NULL;
	}

	req = cli_nt_delete_on_close_send(NULL, self->ev, self->cli, fnum,
					  flag);
	if (!py_tevent_req_wait_exc(self, req)) {
		return NULL;
	}
	status = cli_nt_delete_on_close_recv(req);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *py_cli_list(struct py_cli_state *self,
			     PyObject *args,
			     PyObject *kwds)
{
	char *mask;
	unsigned attribute =
		FILE_ATTRIBUTE_DIRECTORY |
		FILE_ATTRIBUTE_SYSTEM |
		FILE_ATTRIBUTE_HIDDEN;
	unsigned info_level = SMB_FIND_FILE_BOTH_DIRECTORY_INFO;
	struct tevent_req *req;
	NTSTATUS status;
	struct file_info *finfos;
	size_t i, num_finfos;
	PyObject *result;

	const char *kwlist[] = {
		"mask", "attribute", "info_level", NULL
	};

	if (!ParseTupleAndKeywords(
		    args, kwds, "s|II", kwlist,
		    &mask, &attribute, &info_level)) {
		return NULL;
	}

	req = cli_list_send(NULL, self->ev, self->cli, mask, attribute,
			    info_level);
	if (!py_tevent_req_wait_exc(self, req)) {
		return NULL;
	}
	status = cli_list_recv(req, NULL, &finfos, &num_finfos);
	TALLOC_FREE(req);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS(status);
		return NULL;
	}

	result = Py_BuildValue("[]");
	if (result == NULL) {
		return NULL;
	}

	for (i=0; i<num_finfos; i++) {
		struct file_info *finfo = &finfos[i];
		PyObject *file;
		int ret;

		file = Py_BuildValue(
			"{s:s,s:i}",
			"name", finfo->name,
			"mode", (int)finfo->mode);
		if (file == NULL) {
			Py_XDECREF(result);
			return NULL;
		}

		ret = PyList_Append(result, file);
		if (ret == -1) {
			Py_XDECREF(result);
			return NULL;
		}
	}

	return result;
}

static PyMethodDef py_cli_state_methods[] = {
	{ "settimeout", (PyCFunction)py_cli_settimeout, METH_VARARGS,
	  "settimeout(new_timeout_msecs) => return old_timeout_msecs" },
	{ "create", (PyCFunction)py_cli_create, METH_VARARGS|METH_KEYWORDS,
	  "Open a file" },
	{ "close", (PyCFunction)py_cli_close, METH_VARARGS,
	  "Close a file handle" },
	{ "write", (PyCFunction)py_cli_write, METH_VARARGS|METH_KEYWORDS,
	  "Write to a file handle" },
	{ "read", (PyCFunction)py_cli_read, METH_VARARGS|METH_KEYWORDS,
	  "Read from a file handle" },
	{ "truncate", (PyCFunction)py_cli_ftruncate,
	  METH_VARARGS|METH_KEYWORDS,
	  "Truncate a file" },
	{ "delete_on_close", (PyCFunction)py_cli_delete_on_close,
	  METH_VARARGS|METH_KEYWORDS,
	  "Set/Reset the delete on close flag" },
	{ "readdir", (PyCFunction)py_cli_list,
	  METH_VARARGS|METH_KEYWORDS,
	  "List a directory" },
	{ "get_oplock_break", (PyCFunction)py_cli_get_oplock_break,
	  METH_VARARGS, "Wait for an oplock break" },
	{ NULL, NULL, 0, NULL }
};

static PyTypeObject py_cli_state_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libsmb_samba_internal.Conn",
	.tp_basicsize = sizeof(struct py_cli_state),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "libsmb connection",
	.tp_new = py_cli_state_new,
	.tp_init = (initproc)py_cli_state_init,
	.tp_dealloc = (destructor)py_cli_state_dealloc,
	.tp_methods = py_cli_state_methods,
};

static PyMethodDef py_libsmb_methods[] = {
	{ NULL },
};

void initlibsmb_samba_internal(void);

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "libsmb_samba_internal",
    .m_doc = "libsmb wrapper",
    .m_size = -1,
    .m_methods = py_libsmb_methods,
};

MODULE_INIT_FUNC(libsmb_samba_internal)
{
	PyObject *m = NULL;

	talloc_stackframe();

	m = PyModule_Create(&moduledef);
	if (m == NULL) {
		return m;
	}
	if (PyType_Ready(&py_cli_state_type) < 0) {
		return NULL;
	}
	Py_INCREF(&py_cli_state_type);
	PyModule_AddObject(m, "Conn", (PyObject *)&py_cli_state_type);
	return m;
}
