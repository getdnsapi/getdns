/**
 * \file
 * unit tests for getdns_dict helper routines, these should be used to
 * perform regression tests, output must be unchanged from canonical output
 * stored with the sources
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "testmessages.h"
#include "getdns_core_only.h"

#define TSTMSGBUF 80

/*---------------------------------------- tst_intsetget */
/**
 * test the int get and set routines 
 */
void
tst_intsetget(void)
{
    char   msg[TSTMSGBUF];
    char   key[20];
    uint32_t ans_int; 
    uint32_t newint; 
    getdns_return_t    retval;
    struct getdns_dict *dict = NULL;

    tstmsg_case_begin("tst_intsetget");

    dict = getdns_dict_create();

    /* test int get function against empty list and with bogus params */

    strcpy(key, "foo");

    tstmsg_case_msg("getdns_dict_get_int() empty dict");
    retval = getdns_dict_get_int(NULL, key, &ans_int);
    sprintf(msg, "line %d: getdns_dict_get_int(NULL, key, &ans_int),retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    retval = getdns_dict_get_int(dict, key, NULL);
    sprintf(msg, "line %d: getdns_dict_get_int(dict, key, NULL),retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_int(dict, NULL, &ans_int)");
    retval = getdns_dict_get_int(dict, NULL, &ans_int);
    sprintf(msg, "line %d: getdns_dict_get_int,retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_int(dict, key, &ans_int)");
    retval = getdns_dict_get_int(dict, key, &ans_int);
    sprintf(msg, "line %d: getdns_list_get_int,retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);

    /* TODO: test getdns_dict_set functions with bogus params */

    /* test set and get legitimate use case */

    dict = getdns_dict_create();

    strcpy(key, "foo");
    newint = 42;

    tstmsg_case_msg("getdns_dict_set_int(dict, key, newint)");
    retval = getdns_dict_set_int(dict, key, newint);
    sprintf(msg, "line %d: getdns_dict_set_int,retval=%d,key=%s,int=%d", __LINE__, retval, key, newint);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_int(dict, key, &ans_int)");
    retval = getdns_dict_get_int(dict, key, &ans_int);
    sprintf(msg, "line %d: getdns_dict_get_int,retval=%d,key=%s,int=%d", __LINE__, retval, key, ans_int);
    tstmsg_case_msg(msg);

    strcpy(key, "bar");
    newint = 52;
    tstmsg_case_msg("getdns_dict_set_int(dict, key, newint)");
    retval = getdns_dict_set_int(dict, key, newint);
    sprintf(msg, "line %d: getdns_dict_set_int,retval=%d,key=%s,int=%d", __LINE__, retval, key, newint);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_int(dict, key, &ans_int)");
    retval = getdns_dict_get_int(dict, key, &ans_int);
    sprintf(msg, "line %d: getdns_dict_get_int,retval=%d,key=%s,int=%d", __LINE__, retval, key, ans_int);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);

    tstmsg_case_end();

    return;
} /* tst_intsetget */

/*---------------------------------------- tst_create */
/**
 * test the create, destroy and allocation functions
 */
void
tst_create(void)
{
    struct getdns_dict *dict = NULL;

    /* make sure we can do a simple create/destroy first */

    tstmsg_case_begin("tst_create");

    tstmsg_case_msg("getdns_dict_create");
    dict = getdns_dict_create();

    if(dict != NULL)
    {
        tstmsg_case_msg("getdns_dict_destroy(dict)");
        getdns_dict_destroy(dict);
    }

    tstmsg_case_msg("getdns_dict_destroy(NULL)");
    getdns_dict_destroy(NULL);

    tstmsg_case_end();

    return;
} /* tst_create */

/*---------------------------------------- main */
/**
 *  runs unit tests against list management routines
 */
int
main(int argc, char *argv[])
{
    tstmsg_prog_begin("tests_dict");

    tst_create();

    tst_intsetget();

/*
    tst_listsetget();

    tst_bindatasetget();

    tstmsg_prog_end();
*/
    return 0;
} /* main */

/* end tests_dict.c */
