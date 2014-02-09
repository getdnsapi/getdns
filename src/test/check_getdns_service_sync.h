#ifndef _check_getdns_service_sync_h_
#define _check_getdns_service_sync_h_

    /*
     *************************************************************
     *                                                           *
     *  T E S T S  F O R  G E T D N S _ S E R V I C E _ S Y N C  * 
     *                                                           *
     *************************************************************
    */

     START_TEST (getdns_service_sync_1)
     {
      /*
       *  context = NULL
       *  expect: GETDNS_RETURN_BAD_CONTEXT
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;

       ASSERT_RC(getdns_service_sync(context, "google.com", NULL, &response), 
         GETDNS_RETURN_BAD_CONTEXT, "Return code from getdns_service_sync()");
     }
     END_TEST

     START_TEST (getdns_service_sync_2)
     {
      /*
       *  name = NULL
       *  expect: GETDNS_RETURN_BAD_CONTEXT
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_service_sync(context, NULL, NULL, &response), 
         GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_service_sync()");
     }
     END_TEST

     START_TEST (getdns_service_sync_3)
     {
      /*
       *  name is invalid (domain name length > 255)
       *  expect: GETDNS_RETURN_BAD_DOMAIN_NAME
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
       const char *name = "oh.my.gosh.and.for.petes.sake.are.you.fricking.crazy.man.because.this.spectacular.and.elaborately.thought.out.domain.name.of.very.significant.length.is.just.too.darn.long.because.you.know.the rfc.states.that.two.hundred.fifty.five.characters.is.the.max.com";

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_service_sync(context, name, NULL, &response), 
         GETDNS_RETURN_BAD_DOMAIN_NAME, "Return code from getdns_service_sync()");
     }
     END_TEST

     START_TEST (getdns_service_sync_4)
     {
      /*
       *  name is invalid (domain name label length > 63)
       *  expect: GETDNS_RETURN_BAD_DOMAIN_NAME
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
       const char *name = "this.domain.hasalabelwhichexceedsthemaximumdnslabelsizeofsixtythreecharacters.com";

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_service_sync(context, name, NULL, &response), 
         GETDNS_RETURN_BAD_DOMAIN_NAME, "Return code from getdns_service_sync()");
     }
     END_TEST

     START_TEST (getdns_service_sync_5)
     {
      /*
       *  response is NULL
       *  expect: GETDNS_RETURN_INVALID_PARAMETER
       */
       struct getdns_context *context = NULL;   

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_service_sync(context, "google.com", NULL, NULL), 
         GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_service_sync()");
     }
     END_TEST

     START_TEST (getdns_service_sync_7)
     {
      /*
       *  rname is <non-existent domain name> (NXDOMAIN)
       *  no extensions
       *  expected: NXDOMAIN response (with SOA record)

       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
       const char *name = "labelsizeofsixtythreecharacterscom";

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_service_sync(context, name, NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_service_sync()");

       EXTRACT_RESPONSE;

       assert_nxdomain(&ex_response);
       assert_nodata(&ex_response);
       assert_soa_in_authority(&ex_response);
     }
     END_TEST



     
     Suite *
     getdns_service_sync_suite (void)
     {
       Suite *s = suite_create ("getdns_service_sync()");
     
       /* Negative test caseis */
       TCase *tc_neg = tcase_create("Negative");
       tcase_add_test(tc_neg, getdns_service_sync_1);
       tcase_add_test(tc_neg, getdns_service_sync_2);
       tcase_add_test(tc_neg, getdns_service_sync_3);
       tcase_add_test(tc_neg, getdns_service_sync_4);
       tcase_add_test(tc_neg, getdns_service_sync_5);
       
       suite_add_tcase(s, tc_neg);
     
       /* Positive test cases */
       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_service_sync_7);
       suite_add_tcase(s, tc_pos);
     
       return s;
     }

#endif