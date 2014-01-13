#ifndef _check_getdns_address_h_
#define _check_getdns_address_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ A D D R E S S _ S Y N C               *
     *                                                                        *
     **************************************************************************
    */
 
     START_TEST (getdns_address_sync_1)
     {
      /*
       *  context = NULL
       *  expect: GETDNS_RETURN_BAD_CONTEXT
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;

       ASSERT_RC(getdns_address_sync(context, "google.com", NULL, &response), 
         GETDNS_RETURN_BAD_CONTEXT, "Return code from getdns_address_sync()");
     }
     END_TEST
     
     START_TEST (getdns_address_sync_2)
     {
      /*
       *  name = NULL
       *  expect: GETDNS_RETURN_INVALID_PARAMETER
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, NULL, NULL, &response), 
         GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_address_sync()");

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_3)
     {
      /*
       *  name = invalid domain (too many octets)
       *  expect:  GETDNS_RETURN_BAD_DOMAIN_NAME
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
       const char *name = "oh.my.gosh.and.for.petes.sake.are.you.fricking.crazy.man.because.this.spectacular.and.elaborately.thought.out.domain.name.of.very.significant.length.is.just.too.darn.long.because.you.know.the rfc.states.that.two.hundred.fifty.five.characters.is.the.max.com";

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, name, NULL, &response), 
         GETDNS_RETURN_BAD_DOMAIN_NAME, "Return code from getdns_address_sync()");

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_4)
     {
      /*
       *  name = invalid domain (label too long)
       *  expect: GETDNS_RETURN_BAD_DOMAIN_NAME
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
       const char *name = "this.domain.hasalabelwhichexceedsthemaximumdnslabelsizeofsixtythreecharacters.com";

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, name, NULL, &response), 
         GETDNS_RETURN_BAD_DOMAIN_NAME, "Return code from getdns_address_sync()");

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_5)
     {
      /*
       *  response = NULL
       *  expect:  GETDNS_RETURN_INVALID_PARAMETER
       */
       struct getdns_context *context = NULL;   

       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, "google.com", NULL, NULL), 
         GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_address_sync()");

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_6)
     {
      /*
       *  name = "google.com"
       *  expect: NOERROR response:
       *    status = GETDNS_RETURN_GOOD
       *    rcode = 0
         todo:  create zonefile with exact count
       *    ancount = tbd (number of records in ANSWER section)
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, "google.com", NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");

       EXTRACT_RESPONSE;

       assert_noerror(&ex_response);

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_7)
     {
      /*
       *  name = "localhost"
       *  expect: NOERROR response:
       *  expect:  GETDNS_RETURN_GOOD
       *    rcode = 0
         todo:  investigate that proper search order is set for resolution (is local being checked)
         todo:  create zonefile with exact count
       *    ancount = tbd (number of records in ANSWER section)
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, "localhost", NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");

       EXTRACT_RESPONSE;

       assert_noerror(&ex_response);

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_8)
     {
      /*
       *  name = "google.joe"
       *    status = GETDNS_RETURN_GOOD for NXDOMAIN
       *    expect: NXDOMAIN response with SOA record
       *    rcode = 0
         todo:  investigate that proper search order is set for resolution (is local being checked)
         todo:  create host file with exact count 
       *    ancount >= 1 (number of records in ANSWER section)
       *      and one SOA record ("type": 6) in "answer" list
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, "google.joe", NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");

       EXTRACT_RESPONSE;

       assert_nxdomain(&ex_response);
       assert_nodata(&ex_response);
       assert_soa_in_authority(&ex_response);

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_9)
     {
      /*
       *  name = "hampster.com"  need to replace this with domain from unbound zone
       *  expect: NOERROR/NODATA response:
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount = 0 (number of records in ANSWER section)
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, "hampster.com", NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");

       EXTRACT_RESPONSE;

       assert_noerror(&ex_response);

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_10)
     {
      /*
       *    name = "google.com"  need to swap this out for max domain name length with max lable length`
       *    expect: NOERROR response with A records
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount >= 11 (number of records in ANSWER section)
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, "google.com", NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");

       EXTRACT_RESPONSE;

       assert_noerror(&ex_response);
       assert_address_in_answer(&ex_response, TRUE, FALSE);

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_11)
     {
      /*
       *  name = "75.101.146.66"  need to change this to local unbound data
       *    status = GETDNS_RETURN_GOOD for NXDOMAIN
       *    expect: NXDOMAIN response with SOA record for NUMERICAL data 
       *    rcode = 0
       *    ancount >= 1 (number of records in ANSWER section)
       *      and one SOA record ("type": 6) in "answer" list
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, "75.101.146.66", NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");

       EXTRACT_RESPONSE;

       assert_nxdomain(&ex_response);
       assert_nodata(&ex_response);
       assert_soa_in_authority(&ex_response);

       CONTEXT_DESTROY;
     }
     END_TEST
     
     START_TEST (getdns_address_sync_12)
     {
      /*
       *  name = "2607:f8b0:4006:802::1007"  need to change this to local unbound data
       *    status = GETDNS_RETURN_GOOD for NXDOMAIN
       *    expect: NXDOMAIN response with SOA record for NUMERICAL data 
       *    rcode = 0
       *    ancount >= 1 (number of records in ANSWER section)
       *      and one SOA record ("type": 6) in "answer" list
       */
       struct getdns_context *context = NULL;   
       struct getdns_dict *response = NULL;
     
       CONTEXT_CREATE(TRUE);

       ASSERT_RC(getdns_address_sync(context, "2607:f8b0:4006:802::1007", NULL, &response),
         GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");

       EXTRACT_RESPONSE;

       assert_nxdomain(&ex_response);
       assert_nodata(&ex_response);
       assert_soa_in_authority(&ex_response);

       CONTEXT_DESTROY;
     }
     END_TEST

     Suite *
     getdns_address_sync_suite (void)
     {
       Suite *s = suite_create ("getdns_address_sync()");
     
       /* Negative test caseis */
       TCase *tc_neg = tcase_create("Negative");
       tcase_add_test(tc_neg, getdns_address_sync_1);
       tcase_add_test(tc_neg, getdns_address_sync_2);
       tcase_add_test(tc_neg, getdns_address_sync_3);
       tcase_add_test(tc_neg, getdns_address_sync_4);
       tcase_add_test(tc_neg, getdns_address_sync_5);
       suite_add_tcase(s, tc_neg);
       /* Positive test cases */

       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_address_sync_6);
       tcase_add_test(tc_pos, getdns_address_sync_7);
       tcase_add_test(tc_pos, getdns_address_sync_8);
       tcase_add_test(tc_pos, getdns_address_sync_9);
       tcase_add_test(tc_pos, getdns_address_sync_10);
       tcase_add_test(tc_pos, getdns_address_sync_11);
       tcase_add_test(tc_pos, getdns_address_sync_12);
       suite_add_tcase(s, tc_pos);
     
       return s;
     }

#endif
