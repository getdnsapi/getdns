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
#include <getdns/getdns.h>

#define TSTMSGBUF 80

/*---------------------------------------- tst_bindatasetget */
/**
 * test the bindata get and set routines 
 */
void
tst_bindatasetget(void)
{
    char   msg[TSTMSGBUF];
    char   key[20];
    getdns_return_t    retval;
    struct getdns_dict *dict = NULL;
    struct getdns_bindata *ans_bdata;
    struct getdns_bindata *bindata;

    tstmsg_case_begin("tst_bindatasetget");

    dict = getdns_dict_create();

    /* test int get function against empty dict and with bogus params */

    strcpy(key, "foo");

    tstmsg_case_msg("getdns_dict_get_bindata() empty dict");
    retval = getdns_dict_get_bindata(NULL, key, &ans_bdata);
    sprintf(msg, "line %d: getdns_dict_get_bindata(NULL, key, &ans_bdata),retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    retval = getdns_dict_get_bindata(dict, key, NULL);
    sprintf(msg, "line %d: getdns_dict_get_bindata(dict, key, NULL),retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_bindata(dict, NULL, &ans_bindata)");
    retval = getdns_dict_get_bindata(dict, NULL, &ans_bdata);
    sprintf(msg, "line %d: getdns_dict_get_bindata,retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_bindata(dict, key, &ans_bdata)");
    retval = getdns_dict_get_bindata(dict, key, &ans_bdata);
    sprintf(msg, "line %d: getdns_list_get_bindata,retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);

    /* TODO: test getdns_dict_set functions with bogus params */

    /* test set and get legitimate use case */

    dict = getdns_dict_create();

    strcpy(key, "foo");
    bindata = (struct getdns_bindata *) malloc(sizeof(struct getdns_bindata));
    bindata->size = strlen("foobar") + 1;
    bindata->data = (void *) strdup("foobar");

    tstmsg_case_msg("getdns_dict_set_bindata(dict, key, bindata)");
    retval = getdns_dict_set_bindata(dict, key, bindata);
    sprintf(msg, "line %d: getdns_dict_set_bindata,retval=%d,key=%s", __LINE__, retval, key);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_bindata(dict, key, &ans_bdata)");
    retval = getdns_dict_get_bindata(dict, key, &ans_bdata);
    sprintf(msg, "line %d: getdns_dict_get_bindata,retval=%d,key=%s,data=%s", __LINE__, retval, key, ans_bdata->data);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);
    free(bindata->data);
    free(bindata);

    tstmsg_case_end();

    return;
} /* tst_bindatasetget */

/*---------------------------------------- tst_dictsetget */
/**
 * test the dict get and set routines 
 */
void
tst_dictsetget(void)
{
    char     msg[TSTMSGBUF];
    char     key[20];
    uint32_t int1;
    uint32_t int2;
    getdns_return_t    retval;
    struct getdns_dict *newdict; 
    struct getdns_dict *ansdict; 
    struct getdns_dict *dict = NULL;

    tstmsg_case_begin("tst_dictsetget");

    dict = getdns_dict_create();

    /* test get function against empty list and with bogus params */

    strcpy(key, "foo");

    tstmsg_case_msg("getdns_dict_get_dict() empty dict");
    retval = getdns_dict_get_dict(NULL, key, &ansdict);
    sprintf(msg, "line %d: getdns_dict_get_dict(NULL, key, &ansdict),retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    retval = getdns_dict_get_dict(dict, key, NULL);
    sprintf(msg, "line %d: getdns_dict_get_dict(dict, key, NULL),retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_dict(dict, NULL, &ansdict)");
    retval = getdns_dict_get_dict(dict, NULL, &ansdict);
    sprintf(msg, "line %d: getdns_dict_get_dict,retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_dict(dict, key, &ansdict)");
    retval = getdns_dict_get_dict(dict, key, &ansdict);
    sprintf(msg, "line %d: getdns_list_get_dict,retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);

    /* TODO: test getdns_dict_set functions with bogus params */

    /* test set and get legitimate use case */

    dict = getdns_dict_create();

    strcpy(key, "foo");
    newdict = getdns_dict_create();
    getdns_dict_set_int(newdict, "foo", 42);
    getdns_dict_set_int(newdict, "bar", 52);

    tstmsg_case_msg("getdns_dict_set_dict(dict, key, newdict)");
    retval = getdns_dict_set_dict(dict, key, newdict);
    sprintf(msg, "line %d: getdns_dict_set_dict,retval=%d,key=%s", __LINE__, retval, key);
    tstmsg_case_msg(msg);
    getdns_dict_destroy(newdict);

    tstmsg_case_msg("getdns_dict_get_dict(dict, key, &ansdict)");
    retval = getdns_dict_get_dict(dict, key, &ansdict);
    getdns_dict_get_int(ansdict, "foo", &int1);
    getdns_dict_get_int(ansdict, "bar", &int2);
    sprintf(msg, "line %d: getdns_dict_get_dict,retval=%d,key=%s,int1=%d,int2=%d"
     , __LINE__, retval, key, int1, int2);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);

    tstmsg_case_end();

    return;
} /* tst_dictsetget */

/*---------------------------------------- tst_getnames */
/**
 * exercise the getdns_dict_get_names function
 */
void
tst_getnames(void)
{
    size_t index;
    size_t llen;
    uint32_t ansint;
    int    i;
    getdns_return_t    result;
    getdns_data_type   dtype;
    struct getdns_dict *dict = NULL;
    struct getdns_list *list = NULL;

    tstmsg_case_begin("tst_getnames");

    dict = getdns_dict_create();

    /* degenerative use cases */

    tstmsg_case_msg("getdns_dict_get_names(NULL, &list)");
    getdns_dict_get_names(NULL, &list);

    tstmsg_case_msg("getdns_dict_get_names(dict, NULL)");
    getdns_dict_get_names(dict, NULL);

    tstmsg_case_msg("getdns_dict_get_names(dict, &list), empty dictionary");
    getdns_dict_get_names(dict, &list);

    /* legit use case, add items out of order to exercise tree */
    /* TODO: add elements of type dict, bindata, list to the dict */

    i = 0;
    getdns_dict_set_int(dict, "foo", i++);
    getdns_dict_set_int(dict, "bar", i++);
    getdns_dict_set_int(dict, "quz", i++);
    getdns_dict_set_int(dict, "alpha", i++);

    getdns_dict_get_names(dict, &list);

    result = getdns_list_get_length(list, &llen);
    if(llen != i)
    {
        tstmsg_case_msg("getdns_list_get_length returned unreasonable length, exiting");
        return;
    }

    for(index=0; index<llen; index++)
    {
        getdns_list_get_data_type(list, index, &dtype);
        printf("    list item %d: ", (int) index);
        switch(dtype)
        {
            case t_bindata:
                printf("NOTIMPLEMENTED");
                break;

            case t_dict:
                printf("NOTIMPLEMENTED");
                break;

            case t_int:
                getdns_list_get_int(list, index, &ansint);
                printf("t_int, value=%d\n", ansint);
                break;

            case t_invalid:
                printf("data type invalid");
                break;

            case t_list:
                printf("NOTIMPLEMENTED");
                break;
        }
    }

    getdns_dict_destroy(dict);

    tstmsg_case_end();
} /* tst_getnames */

/*---------------------------------------- tst_listsetget */
/**
 * test the list get and set routines 
 */
void
tst_listsetget(void)
{
    char     msg[TSTMSGBUF];
    char     key[20];
    size_t   index;
    uint32_t int1;
    uint32_t int2;
    getdns_return_t    retval;
    struct getdns_list *newlist; 
    struct getdns_list *anslist; 
    struct getdns_dict *dict = NULL;

    tstmsg_case_begin("tst_listsetget");

    dict = getdns_dict_create();

    /* test get function against empty list and with bogus params */

    strcpy(key, "foo");

    tstmsg_case_msg("getdns_dict_get_list() empty dict");
    retval = getdns_dict_get_list(NULL, key, &anslist);
    sprintf(msg, "line %d: getdns_dict_get_list(NULL, key, &anslist),retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    retval = getdns_dict_get_list(dict, key, NULL);
    sprintf(msg, "line %d: getdns_dict_get_list(dict, key, NULL),retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_list(dict, NULL, &anslist)");
    retval = getdns_dict_get_list(dict, NULL, &anslist);
    sprintf(msg, "line %d: getdns_dict_get_list,retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    tstmsg_case_msg("getdns_dict_get_list(dict, key, &anslist)");
    retval = getdns_dict_get_list(dict, key, &anslist);
    sprintf(msg, "line %d: getdns_list_get_list,retval = %d", __LINE__, retval);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);

    /* TODO: test getdns_dict_set functions with bogus params */

    /* test set and get legitimate use case */

    dict = getdns_dict_create();

    strcpy(key, "foo");
    newlist = getdns_list_create();
    getdns_list_add_item(newlist, &index);
    getdns_list_set_int(newlist, index, 42);
    getdns_list_add_item(newlist, &index);
    getdns_list_set_int(newlist, index, 52);

    tstmsg_case_msg("getdns_dict_set_list(dict, key, newlist)");
    retval = getdns_dict_set_list(dict, key, newlist);
    sprintf(msg, "line %d: getdns_dict_set_list,retval=%d,key=%s", __LINE__, retval, key);
    tstmsg_case_msg(msg);
    getdns_list_destroy(newlist);

    tstmsg_case_msg("getdns_dict_get_list(dict, key, &anslist)");
    retval = getdns_dict_get_list(dict, key, &anslist);
    getdns_list_get_int(anslist, 0, &int1);
    getdns_list_get_int(anslist, 1, &int2);
    sprintf(msg, "line %d: getdns_dict_get_list,retval=%d,key=%s,int1=%d,int2=%d"
     , __LINE__, retval, key, int1, int2);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);

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
    char   key[20];
    uint32_t ans_int; 
    uint32_t newint; 
    getdns_return_t    retval;
    struct getdns_dict *dict = NULL;
    getdns_data_type dtype;

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

    tstmsg_case_msg("getdns_dict_get_data_type(dict, key, &dtype)");
    retval = getdns_dict_get_data_type(dict, key, &dtype);
    sprintf(msg, "line %d: getdns_dict_get_data_type,retval=%d,key=%s,dtype=%d", __LINE__, retval, key, dtype);
    tstmsg_case_msg(msg);

    getdns_dict_destroy(dict);

    tstmsg_case_end();

    return;
} /* tst_intsetget */

/*---------------------------------------- tst_copy */
/**
 * test the copy and pretty print functions
 */
void
tst_copy(void)
{
    char *dictstr = NULL;
    struct getdns_dict *dict1 = NULL;
    struct getdns_dict *dict2 = NULL;

    tstmsg_case_begin("tst_copy");

    tstmsg_case_msg("empty list cases");

    getdns_dict_copy(NULL, NULL);
    dict1 = getdns_dict_create();
    getdns_dict_copy(dict1, &dict2);
    getdns_dict_copy(NULL, &dict1);

    tstmsg_case_msg("dict1 populate");

    getdns_dict_set_int(dict1, "foo", 42);
    getdns_dict_set_int(dict1, "bar", 52);
    getdns_dict_set_int(dict1, "quz", 62);

    dictstr = getdns_pretty_print_dict(dict1);
    printf("%s", dictstr);
    free(dictstr);

    tstmsg_case_msg("getdns_dict_copy(dict1, &dict2)");

    getdns_dict_copy(dict1, &dict2);

    dictstr = getdns_pretty_print_dict(dict2);
    printf("%s", dictstr);
    free(dictstr);

    getdns_dict_destroy(dict1);
    getdns_dict_destroy(dict2);

    tstmsg_case_end();

    return;
} /* tst_copy */

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

    tst_bindatasetget();

    tst_dictsetget();

    tst_intsetget();

    tst_listsetget();

    tst_getnames();

    tst_copy();

    tstmsg_prog_end();

    return 0;
} /* main */

/* end tests_dict.c */
