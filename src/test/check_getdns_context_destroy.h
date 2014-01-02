#ifndef _check_getdns_context_destroy_h_
#define _check_getdns_context_destroy_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ C O N T E X T _ D E S T R O Y         *
     *                                                                        *
     **************************************************************************
    */

     START_TEST (getdns_context_destroy_1)
     {
      /*
       *  context = NULL
       *  expect: nothing, no segmentation fault
       */

       getdns_context_destroy(NULL);
     }
     END_TEST
     
     START_TEST (getdns_context_destroy_2)
     {
      /*
       *  destroy called with valid context and no outstanding transactions
       *  expect: nothing, context is freed 
       */
       struct getdns_context *context = NULL;

       CONTEXT_CREATE(TRUE);
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_context_destroy_3)
     {
      /*
       *  destroy called immediately following getdns_general
       *  expect: callback should be called before getdns_context_destroy() returns
       */
       void verify_getdns_context_destroy(struct extracted_response *ex_response);
       struct getdns_context *context = NULL;
       struct event_base *event_base = NULL;
       getdns_transaction_t transaction_id = 0;

       CONTEXT_CREATE(TRUE);
       EVENT_BASE_CREATE;
       
       ASSERT_RC(getdns_general(context, "google.com", GETDNS_RRTYPE_A, NULL,
         verify_getdns_context_destroy, &transaction_id, callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");

       RUN_EVENT_LOOP;
       CONTEXT_DESTROY;

       ck_assert_msg(callback_called == 1, "callback_called should == 1, got %d", callback_called);
     }
     END_TEST
     
     START_TEST (getdns_context_destroy_4)
     {
      /*
       *  destroy called immediately following getdns_address
       *  expect: callback should be called before getdns_context_destroy() returns
       */
       void verify_getdns_context_destroy(struct extracted_response *ex_response);
       struct getdns_context *context = NULL;
       struct event_base *event_base = NULL;
       getdns_transaction_t transaction_id = 0;

       CONTEXT_CREATE(TRUE);
       EVENT_BASE_CREATE;
       
       ASSERT_RC(getdns_address(context, "8.8.8.8", NULL,
         verify_getdns_context_destroy, &transaction_id, callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_address()");

       RUN_EVENT_LOOP;
       CONTEXT_DESTROY;

       ck_assert_msg(callback_called == 1, "callback_called should == 1, got %d", callback_called);
     }
     END_TEST
     
     START_TEST (getdns_context_destroy_5)
     {
      /*
       *  destroy called immediately following getdns_address
       *  expect: callback should be called before getdns_context_destroy() returns
       */
       void verify_getdns_context_destroy(struct extracted_response *ex_response);
       struct getdns_context *context = NULL;
       struct event_base *event_base = NULL;
       struct getdns_bindata address_type = { 5, (void *)"IPv4" };
       struct getdns_bindata address_data = { 4, (void *)"\x08\x08\x08\x08" };
       struct getdns_dict *address = NULL;
       getdns_transaction_t transaction_id = 0;

       CONTEXT_CREATE(TRUE);
       EVENT_BASE_CREATE;

       DICT_CREATE(address);
       ASSERT_RC(getdns_dict_set_bindata(address, "address_type", &address_type),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata");
       ASSERT_RC(getdns_dict_set_bindata(address, "address_data", &address_data),
         GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata");
       
       ASSERT_RC(getdns_hostname(context, address, NULL,
         verify_getdns_context_destroy, &transaction_id, callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_address()");

       RUN_EVENT_LOOP;
       CONTEXT_DESTROY;

       ck_assert_msg(callback_called == 1, "callback_called should == 1, got %d", callback_called);
     }
     END_TEST
     
     START_TEST (getdns_context_destroy_6)
     {
      /*
       *  destroy called immediately following getdns_address
       *  expect: callback should be called before getdns_context_destroy() returns
       */
       void verify_getdns_context_destroy(struct extracted_response *ex_response);
       struct getdns_context *context = NULL;
       struct event_base *event_base = NULL;
       getdns_transaction_t transaction_id = 0;

       CONTEXT_CREATE(TRUE);
       EVENT_BASE_CREATE;
       
       ASSERT_RC(getdns_service(context, "google.com", NULL,
         verify_getdns_context_destroy, &transaction_id, callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_service()");

       RUN_EVENT_LOOP;
       CONTEXT_DESTROY;

       ck_assert_msg(callback_called == 1, "callback_called should == 1, got %d", callback_called);
     }
     END_TEST

     void verify_getdns_context_destroy(struct extracted_response *ex_response)
     {
       /*
        * Sleep for a second to make getdns_context_destroy() wait.
        */
       sleep(1);

       /*
        *  callback_called is a global and we increment it
        *  here to show that the callback was called.
        */
       callback_called++;
     }

     Suite *
     getdns_context_destroy_suite (void)
     {
       Suite *s = suite_create ("getdns_context_destroy()");

       /* Negative test caseis */
       TCase *tc_neg = tcase_create("Negative");
       tcase_add_test(tc_neg, getdns_context_destroy_1);
       suite_add_tcase(s, tc_neg);

       /* Positive test cases */
       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_context_destroy_2);
       tcase_add_test(tc_pos, getdns_context_destroy_3);
       tcase_add_test(tc_pos, getdns_context_destroy_4);
       tcase_add_test(tc_pos, getdns_context_destroy_5);
       tcase_add_test(tc_pos, getdns_context_destroy_6);
       suite_add_tcase(s, tc_pos);
     
       return s;
     }

#endif
