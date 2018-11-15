/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) 2018      Justin Stephenson
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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <setjmp.h>
#include <errno.h>
#include <cmocka.h>
#include <string.h>
#include <talloc.h>
#include "../tini.h"

/* Maximum number of name=value lines evaluated per section */
#define MAX_NAME_VALUE 10
#define NUM_SAMPLES 2

#define COMMENT_STYLE_ONE ";This is a comment"
#define COMMENT_STYLE_TWO "#This is another comment"
#define DEFAULTS_SECTION "defaults"
#define GLOBAL_SECTION "global"
#define USERNAME_KEY "username"
#define LOGIN_KEY "login"
#define USERNAME_VALUE "testuser"
#define LOGIN_VALUE "tuser8373"

struct tini_parse_ctx {
	TALLOC_CTX *mem_ctx;
	int name_value_count;
	const char *section;
	char *output_str; /* section:name:value */
};

static bool get_section(const char *section,
			  void *private_data)
{
	struct tini_parse_ctx *inictx = (struct tini_parse_ctx *)private_data;

	inictx->section = talloc_strdup(inictx->mem_ctx, section);
	printf("Parsing section: %s\n", inictx->section);
	return true;

}

static bool store_key_values(const char *name,
			     const char *value,
			     void *private_data)
{
	struct tini_parse_ctx *inictx = (struct tini_parse_ctx *)private_data;

	int count = inictx->name_value_count;

	inictx[count].output_str = talloc_asprintf(inictx->mem_ctx, "%s:%s:%s", inictx->section,
								    name,
								    value);
	assert_non_null(inictx[count].output_str);
	printf("output_str: %s\n", inictx[count].output_str);

	inictx->name_value_count++;

	return true;
}

static void test_tini_parse_single_section(void **state)
{
	struct tini_parse_ctx inictx[MAX_NAME_VALUE];
	char filename[] = "tmp_ini_fileXXXXXX";
	FILE *fp;
	size_t rc;
	int fd;
	bool ok = false;
	char *input = NULL;
	/* expected output format is section:name:value */
	char *expected[NUM_SAMPLES];
	int i;

	TALLOC_CTX *ctx = talloc_new(NULL);
	inictx->mem_ctx = ctx;

	inictx->name_value_count = 0;

	/* ;This is a comment
	 * [defaults]
	 * username=testuser
	 * login=tuser8373
	 * #This is another comment
	 * */
	input = talloc_asprintf(ctx, "%s\n[%s]\n%s=%s\n%s=%s\n%s\n", COMMENT_STYLE_ONE,
								     DEFAULTS_SECTION,
								     USERNAME_KEY,
								     USERNAME_VALUE,
								     LOGIN_KEY,
								     LOGIN_VALUE,
								     COMMENT_STYLE_TWO);

	/* defaults:username:testuser */
	expected[0] = talloc_asprintf(ctx, "%s:%s:%s", DEFAULTS_SECTION,
						       USERNAME_KEY,
						       USERNAME_VALUE);
	/* defaults:login:tuser8375 */
	expected[1] = talloc_asprintf(ctx, "%s:%s:%s", DEFAULTS_SECTION,
						       LOGIN_KEY,
						       LOGIN_VALUE);

	fd = mkstemp(filename);
	fp = fdopen(fd, "w+");
	assert_non_null(fp);

	rc = fwrite(input, 1, strlen(input) + 1, fp);
	assert_return_code(rc, errno);

	rewind(fp);

	ok = tini_parse(fp, true, get_section, store_key_values, &inictx);
	assert_true(ok);

	for (i = 0; i < NUM_SAMPLES; i++) {
		printf("checking\n");
		assert_string_equal(expected[i], inictx[i].output_str);
	}

	fclose(fp);
	unlink(filename);
	talloc_free(ctx);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_tini_parse_single_section),
	};

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
