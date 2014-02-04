#ifndef _check_getdns_hostname_sync_h_
#define _check_getdns_hostname_sync_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ H O S T N A M E _ S Y N C             *
     *                                                                        *
     **************************************************************************
    */

     START_TEST (getdns_hostname_sync_1)
     {
      /*
       *  context = NULL
       *  expect: GETDNS_RETURN_BAD_CONTEXT
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv4" };
       struct getdns_bindata address_data = { 4, (void *)"\x08\x08\x08\x08" };
       struct getdns_dict *response = NULL;

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_BAD_CONTEXT, "Return code from getdns_hostname_sync()");

       DICT_DESTROY(address);
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_2)
     {
      /*
       *  address = NULL
       *  expect: GETDNS_RETURN_INVALID_PARAMETER
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_hostname_sync(context, NULL,  NULL, &response), 
         GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_hostname_sync()");

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_3)
     {
      /*
       *  response = NULL
       *  expect:  GETDNS_RETURN_INVALID_PARAMETER
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv4" };
       struct getdns_bindata address_data = { 4, (void *)"\x08\x08\x08\x08" };

       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, NULL), 
         GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_hostname_sync()");

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_4)
     {
      /*
       *  dict in address does not contain getdns_bindata
       *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *address = NULL;
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);
       DICT_CREATE(address);

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_NO_SUCH_DICT_NAME, "Return code from getdns_hostname_sync()");

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_5)
     {
      /*
       *  dict in address does not contain two names
       *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *) "IPv4" };
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_NO_SUCH_DICT_NAME, "Return code from getdns_hostname_sync()");

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_6)
     {
      /*
       *  dict in address contains names other than adddress_type
       *  and address_data.
       *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_data = { 4, (void *)"\x08\x08\x08\x08" };
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_int(address, "not_address_type", 100),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");
       ASSERT_RC(getdns_dict_set_bindata(address, "not_address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_NO_SUCH_DICT_NAME, "Return code from getdns_hostname_sync()");

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_7)
     {
      /*
       *  dict in address contains names address_type 
       *  and address_data but data type is not bindata
       *  expect:  GETDNS_RETURN_WRONG_TYPE_REQUESTED
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *address = NULL;
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_int(address, "address_type", 100),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");
       ASSERT_RC(getdns_dict_set_int(address, "address_data", 200),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_WRONG_TYPE_REQUESTED, "Return code from getdns_hostname_sync()");

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_8)
     {
      /*
       *  dict in address contains invalid address_type
       *  expect:  GETDNS_RETURN_INVALID_PARAMETER
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv5" };
       struct getdns_bindata address_data = { 4, (void *)"\x08\x08\x08\x08" };
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_hostname_sync()");

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_9)
     {
      /*
       *  dict in address contains invalid address_data
       *  expect:  GETDNS_RETURN_INVALID_PARAMETER
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv4" };
       struct getdns_bindata address_data = { 5, (void *)"\x08\x08\x08\x08\x08" };
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_hostname_sync()");

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_10)
     {
      /*
       *  dict in address has resolvable IPv4 address
       *  expect:  response with correct hostnam
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv4" };
       struct getdns_bindata address_data = { 4, (void *)"\x08\x08\x08\x08" };
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_hostname_sync()");

       EXTRACT_RESPONSE;

       assert_noerror(&ex_response);
       assert_ptr_in_answer(&ex_response);

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_11)
     {
      /*
       *  dict in address has unresolvable IPv4 address
       *  expect:  response with no hostname
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv4" };
       struct getdns_bindata address_data = { 4, (void *)"\x01\x01\x01\x01" };
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_hostname_sync()");

       EXTRACT_RESPONSE;

       assert_nxdomain(&ex_response);
       assert_nodata(&ex_response);
       assert_soa_in_authority(&ex_response);

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_12)
     {
      /*
       *  dict in address has resolvable IPv6 address
       *  expect:  response with correct hostnam
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv6" };
       struct getdns_bindata address_data = { 16, (void *)"\x26\x07\xf8\xb0\x40\x06\x08\x02\x00\x00\x00\x00\x00\x00\x10\x04" };
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_hostname_sync()");

       EXTRACT_RESPONSE;

       assert_noerror(&ex_response);
       assert_ptr_in_answer(&ex_response);

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_hostname_sync_13)
     {
      /*
       *  dict in address has unresolvable IPv6 address
       *  expect:  response with no hostname
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *address = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv6" };
       struct getdns_bindata address_data = { 16, (void *)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" };
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

       ASSERT_RC(getdns_hostname_sync(context, address, NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_hostname_sync()");

       EXTRACT_RESPONSE;

       assert_nxdomain(&ex_response);
       assert_nodata(&ex_response);
       assert_soa_in_authority(&ex_response);

       DICT_DESTROY(address);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     Suite *
     getdns_hostname_sync_suite (void)
     {
       Suite *s = suite_create ("getdns_hostname_sync()");
     
       /* Negative test caseis */
       TCase *tc_neg = tcase_create("Negative");
       tcase_add_test(tc_neg, getdns_hostname_sync_1);
       tcase_add_test(tc_neg, getdns_hostname_sync_2);
       tcase_add_test(tc_neg, getdns_hostname_sync_3);
       tcase_add_test(tc_neg, getdns_hostname_sync_4);
       tcase_add_test(tc_neg, getdns_hostname_sync_5);
       tcase_add_test(tc_neg, getdns_hostname_sync_6);
       tcase_add_test(tc_neg, getdns_hostname_sync_7);
       tcase_add_test(tc_neg, getdns_hostname_sync_8);
       tcase_add_test(tc_neg, getdns_hostname_sync_9);
       suite_add_tcase(s, tc_neg);
       /* Positive test cases */

       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_hostname_sync_10);
       tcase_add_test(tc_pos, getdns_hostname_sync_11);
       tcase_add_test(tc_pos, getdns_hostname_sync_12);
       tcase_add_test(tc_pos, getdns_hostname_sync_13);
       suite_add_tcase(s, tc_pos);
     
       return s;
     }

#endif
