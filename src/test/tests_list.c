/**
 * \file
 * \brief unit tests for getdns_list helper routines 
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
#include "testmessages.h"
#include "getdns_core_only.h"

#define TSTMSGBUF 80

/*---------------------------------------- tst_setget */
/**
 * test the routines that set and get values of items in the list
 */
void
tst_setget(void)
{
    char   msg[TSTMSGBUF];
    size_t index;
    uint32_t ans_int; 
    getdns_return_t    retval;
    struct getdns_list *list = NULL;

    tstmsg_case_begin("tst_setget");

    list = getdns_list_create();

    /* test get functions against empty list and with bogus params */

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
    sprintf(msg, "getdns_list_set_int,retval = %d", retval);
    tstmsg_case_msg(msg);

    getdns_list_destroy(list);

    tstmsg_case_end();

    return;
} /* tst_setget */

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

/**
 *  runs unit tests against list management routines
 */
int
main(int argc, char *argv[])
{
    tstmsg_prog_begin("tests_list");

    tst_create();

    tst_setget();

    tstmsg_prog_end();

    return 0;
} /* main */

/* end tests_list.c */
