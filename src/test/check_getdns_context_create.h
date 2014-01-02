#ifndef _check_getdns_context_create_h_
#define _check_getdns_context_create_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ C O N T E X T _ C R E A T E           *
     *                                                                        *
     **************************************************************************
    */

     START_TEST (getdns_context_create_1)
     {
      /*
       *  context = NULL
       *  expect: GETDNS_RETURN_GENERIC_ERROR
       */

       ASSERT_RC(getdns_context_create(NULL, TRUE),
         GETDNS_RETURN_GENERIC_ERROR, "Return code from getdns_context_create()");
     }
     END_TEST
     
     START_TEST (getdns_context_create_2)
     {
      /*
       *  set_from_os = TRUE
       *  expect: context initialized with operating system info
       *          GETDNS_RETURN_GOOD
       */
       struct getdns_context *context = NULL;

       CONTEXT_CREATE(TRUE);
       //  TODO:  Do something here to verify set_from_os = TRUE 
       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_context_create_3)
     {
      /*
       *  set_from_os = FALSE
       *  expect: context is not initialized with operating system info
       *          GETDNS_RETURN_GOOD
       */
       struct getdns_context *context = NULL;

       CONTEXT_CREATE(FALSE);
       //  TODO:  Do something here to verify set_from_os = TRUE 
       CONTEXT_DESTROY;
     }
     END_TEST

     Suite *
     getdns_context_create_suite (void)
     {
       Suite *s = suite_create ("getdns_context_create()");
     
       /* Negative test caseis */
       TCase *tc_neg = tcase_create("Negative");
       tcase_add_test(tc_neg, getdns_context_create_1);
       suite_add_tcase(s, tc_neg);

       /* Positive test cases */
       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_context_create_2);
       tcase_add_test(tc_pos, getdns_context_create_3);
       suite_add_tcase(s, tc_pos);
     
       return s;
     }

#endif
