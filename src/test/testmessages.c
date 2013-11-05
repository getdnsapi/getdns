/**
 * \file
 * \brief display messages to support unit testing
 */
/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include "testmessages.h"

static char *testprog = NULL;
static char **cases = NULL;
static int ncases = 0;

void
tstmsg_prog_begin(char *prognm)
{
	if (testprog != NULL) {
		tstmsg_prog_end();
		free(testprog);
	}
	testprog = strdup(prognm);
	printf("TESTPROG %s START\n", testprog);
}				/* tstmsg_prog_begin */

void
tstmsg_prog_end()
{
	printf("TESTPROG %s END\n", testprog);
	free(testprog);
}				/* tstmsg_prog_end */

void
tstmsg_case_begin(char *casenm)
{
	ncases++;
	cases = (char **) realloc(cases, sizeof(char *) * ncases);
	cases[ncases - 1] = strdup(casenm);

	printf("TESTCASE %s:%s BEGIN\n", testprog, cases[ncases - 1]);
}				/* tstmsg_case_begin */

void
tstmsg_case_end(void)
{
	if (ncases > 0) {
		printf("TESTCASE %s:%s END\n", testprog, cases[ncases - 1]);
		ncases--;
		free(cases[ncases]);
		if (ncases) {
			cases =
			    (char **) realloc(cases, sizeof(char *) * ncases);
		} else {
			cases = NULL;
		}
	}
}				/* tstmsg_case_end */

void
tstmsg_case_msg(char *msg)
{
	printf("  %s:%s: %s\n", testprog, cases[ncases - 1], msg);
}				/* tstmsg_case_msg */

/* testmessages.c */
