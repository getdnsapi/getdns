/**
 * \file
 * unit tests for getdns_list helper routines, these should be used to
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

/*---------------------------------------- tst_bindatasetget */
/**
 * test the list get and set routines 
 */
void
tst_bindatasetget(void)
{
    char   msg[TSTMSGBUF];
    size_t index;
    getdns_return_t    retval;
    struct getdns_list *list = NULL;
    struct getdns_bindata *new_bindata = NULL; 
    struct getdns_bindata *ans_bindata = NULL; 

    tstmsg_case_begin("tst_bindatasetget");

    list = getdns_list_create();

    /* test get function against empty list and with bogus params */

    tstmsg_case_msg("getdns_list_get_bindata() empty list");
    retval = getdns_list_get_bindata(NULL, index, &ans_bindata);
    sprintf(msg, "getdns_list_get_bindata(NULL, index, &ans_bindata),retval = %d"
     , retval);
    tstmsg_case_msg(msg);

    retval = getdns_list_get_bindata(list, index, NULL);
    sprintf(msg, "getdns_list_get_bindata(list, index, NULL),retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_get_bindata(list, 0, &ans_bindata)");
    retval = getdns_list_get_bindata(list, 0, &ans_bindata);
    sprintf(msg, "getdns_list_get_bindata,retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_get_bindata(list, 1, &ans_bindata)");
    retval = getdns_list_get_bindata(list, 1, &ans_bindata);
    sprintf(msg, "getdns_list_get_bindata,retval = %d", retval);
    tstmsg_case_msg(msg);

    /* test set function against empty list with bogus params */

    tstmsg_case_msg("getdns_list_set_bindata() empty list");
    retval = getdns_list_set_bindata(NULL, index, NULL);
    sprintf(msg, "getdns_list_set_bindata(NULL, index, ans_bindata),retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_set_bindata(list, 0, ans_bindata)");
    retval = getdns_list_set_bindata(list, 0, NULL);
    sprintf(msg, "getdns_list_set_bindata,retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_set_bindata(list, 1, ans_bindata)");
    retval = getdns_list_set_bindata(list, 1, NULL);
    sprintf(msg, "getdns_list_set_bindata,retval = %d", retval);
    tstmsg_case_msg(msg);

    /* test set and get legitimate use case */

    new_bindata = (struct getdns_bindata *) malloc(sizeof(struct getdns_bindata));
    new_bindata->size = strlen("foobar") + 1;
    new_bindata->data = (uint8_t *) strdup("foobar");
    new_bindata->data[strlen("foobar")] = '\0';

    getdns_list_add_item(list, &index);
    getdns_list_set_bindata(list, index, new_bindata);
    retval = getdns_list_get_bindata(list, index, &ans_bindata);
    sprintf(msg, "getdns_list_set/get_bindata,retval = %d, bindata->data = %d,%s"
     , retval, (int) ans_bindata->size, (char *) ans_bindata->data);
    tstmsg_case_msg(msg);

    getdns_list_destroy(list);

    tstmsg_case_end();

    return;
} /* tst_bindatasetget */

/*---------------------------------------- tst_listsetget */
/**
 * test the list get and set routines 
 */
void
tst_listsetget(void)
{
    char   msg[TSTMSGBUF];
    size_t index;
    getdns_return_t    retval;
    uint32_t ans_int; 
    struct getdns_list *list = NULL;
    struct getdns_list *new_list = NULL; 
    struct getdns_list *ans_list = NULL; 

    tstmsg_case_begin("tst_listsetget");

    list = getdns_list_create();

    /* test get function against empty list and with bogus params */

    tstmsg_case_msg("getdns_list_get_list() empty list");
    retval = getdns_list_get_list(NULL, index, &ans_list);
    sprintf(msg, "getdns_list_get_list(NULL, index, &ans_list),retval = %d", retval);
    tstmsg_case_msg(msg);

    retval = getdns_list_get_list(list, index, NULL);
    sprintf(msg, "getdns_list_get_list(list, index, NULL),retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_get_list(list, 0, &ans_list)");
    retval = getdns_list_get_list(list, 0, &ans_list);
    sprintf(msg, "getdns_list_get_list,retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_get_list(list, 1, &ans_list)");
    retval = getdns_list_get_list(list, 1, &ans_list);
    sprintf(msg, "getdns_list_get_list,retval = %d", retval);
    tstmsg_case_msg(msg);

    /* test set function against empty list with bogus params */

    tstmsg_case_msg("getdns_list_set_list() empty list");
    retval = getdns_list_set_list(NULL, index, NULL);
    sprintf(msg, "getdns_list_set_list(NULL, index, ans_list),retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_set_list(list, 0, ans_list)");
    retval = getdns_list_set_list(list, 0, NULL);
    sprintf(msg, "getdns_list_set_list,retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_set_list(list, 1, ans_list)");
    retval = getdns_list_set_list(list, 1, NULL);
    sprintf(msg, "getdns_list_set_list,retval = %d", retval);
    tstmsg_case_msg(msg);

    /* test set and get legitimate use case */

    new_list = getdns_list_create();
    getdns_list_add_item(new_list, &index);
    getdns_list_set_int(new_list, index, 42);

    getdns_list_add_item(list, &index);
    getdns_list_set_list(list, index, new_list);
    retval = getdns_list_get_list(list, index, &ans_list);
    getdns_list_get_int(ans_list, 0, &ans_int);
    sprintf(msg, "getdns_list_set/get_list,retval = %d, ans[0] = %d", retval, ans_int);
    tstmsg_case_msg(msg);

    getdns_list_destroy(list);

    tstmsg_case_end();

    return;
} /* tst_listsetget */

/*---------------------------------------- tst_intsetget */
/**
 * test the int get and set routines 
 */
void
tst_intsetget(void)
{
    char   msg[TSTMSGBUF];
    size_t index;
    uint32_t ans_int; 
    getdns_return_t    retval;
    struct getdns_list *list = NULL;

    tstmsg_case_begin("tst_intsetget");

    list = getdns_list_create();

    /* test int get function against empty list and with bogus params */

    tstmsg_case_msg("getdns_list_get_int() empty list");
    retval = getdns_list_get_int(NULL, index, &ans_int);
    sprintf(msg, "getdns_list_get_int(NULL, index, &ans_int),retval = %d", retval);
    tstmsg_case_msg(msg);

    retval = getdns_list_get_int(list, index, NULL);
    sprintf(msg, "getdns_list_get_int(list, index, NULL),retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_get_int(list, 0, &ans_int)");
    retval = getdns_list_get_int(list, 0, &ans_int);
    sprintf(msg, "getdns_list_get_int,retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_get_int(list, 1, &ans_int)");
    retval = getdns_list_get_int(list, 1, &ans_int);
    sprintf(msg, "getdns_list_get_int,retval = %d", retval);
    tstmsg_case_msg(msg);

    /* test int set function against empty list with bogus params */

    tstmsg_case_msg("getdns_list_set_int() empty list");
    retval = getdns_list_set_int(NULL, index, ans_int);
    sprintf(msg, "getdns_list_set_int(NULL, index, ans_int),retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_set_int(list, 0, ans_int)");
    retval = getdns_list_set_int(list, 0, ans_int);
    sprintf(msg, "getdns_list_set_int,retval = %d", retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_set_int(list, 1, ans_int)");
    retval = getdns_list_set_int(list, 1, ans_int);
    sprintf(msg, "getdns_list_set_int,retval = %d", retval);
    tstmsg_case_msg(msg);

    /* test set and get legitimate use case */

    getdns_list_add_item(list, &index);
    getdns_list_set_int(list, index, 42);
    retval = getdns_list_get_int(list, index, &ans_int);
    sprintf(msg, "getdns_list_set/get_int,retval = %d, ans = %d", retval, ans_int);
    tstmsg_case_msg(msg);

    getdns_list_destroy(list);

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
    char   msg[TSTMSGBUF];
    size_t index;
    int    i;
    getdns_return_t    retval;
    struct getdns_list *list = NULL;

    /* make sure we can do a simple create/destroy first */

    tstmsg_case_begin("tst_create");

    tstmsg_case_msg("getdns_list_create");
    list = getdns_list_create();

    if(list != NULL)
    {
        tstmsg_case_msg("getdns_list_destroy(list)");
        getdns_list_destroy(list);
    }

    tstmsg_case_msg("getdns_list_destroy(NULL)");
    getdns_list_destroy(NULL);

    /* add items until we force it to allocate more storage */

    tstmsg_case_msg("getdns_add_item(list) past block size");
    list = getdns_list_create();
    for(i=0; i<GETDNS_LIST_BLOCKSZ+2; i++)
    {
        retval = getdns_list_add_item(list, &index);
        if(retval != GETDNS_RETURN_GOOD)
        {
            sprintf(msg, "getdns_list_add_item,i=%d,retval = %d", i, retval);
            tstmsg_case_msg(msg);
        }
        else
        {
            if(index != i)
            {
                sprintf(msg, "getdns_list_add_item,i=%d,index=%d,retval = %d"
                 , i, (int) index, retval);
                tstmsg_case_msg(msg);
            }
        }
    }

    tstmsg_case_msg("getdns_list_get_length(list)");
    retval = getdns_list_get_length(list, &index);
    sprintf(msg, "list length = %d", (int) index);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_list_get_length()");
    retval = getdns_list_get_length(NULL, &index);
    sprintf(msg, "NUll, &i, retval = %d", retval);
    tstmsg_case_msg(msg);

    retval = getdns_list_get_length(NULL, NULL);
    sprintf(msg, "NUll, NULL, retval = %d", retval);
    tstmsg_case_msg(msg);

    retval = getdns_list_get_length(list, NULL);
    sprintf(msg, "list, NULL, retval = %d", retval);
    tstmsg_case_msg(msg);

    getdns_list_destroy(list);

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
    tstmsg_prog_begin("tests_list");

    tst_create();

    tst_intsetget();

    tst_listsetget();

    tst_bindatasetget();

    tstmsg_prog_end();

    return 0;
} /* main */

/* end tests_list.c */
