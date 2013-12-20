#ifndef _check_getdns_general_h_
#define _check_getdns_general_h_
     
     START_TEST (getdns_general_1)
     {
      /*
       *  context = NULL
       *  expect: GETDNS_RETURN_BAD_CONTEXT
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
       ASSERT_RC(getdns_general(context, "google.com", GETDNS_RRTYPE_A, NULL, 
         "getdns_general_1", &transaction_id, negative_callbackfn), 
         GETDNS_RETURN_BAD_CONTEXT, "Return code from getdns_general()");
     }
     END_TEST
     
     START_TEST (getdns_general_2)
     {
      /*
       *  name = NULL
       *  expect: GETDNS_RETURN_GENERIC_ERROR
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, NULL, GETDNS_RRTYPE_A, NULL,
         "getdns_general_2", &transaction_id, negative_callbackfn),
         GETDNS_RETURN_GENERIC_ERROR, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_3)
     {
      /*
       *  name = invalid domain (too many octets)
       *  expect:  GETDNS_RETURN_BAD_DOMAIN_NAME
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
       const char *name = "oh.my.gosh.and.for.petes.sake.are.you.fricking.crazy.man.because.this.spectacular.and.elaborately.thought.out.domain.name.of.very.significant.length.is.just.too.darn.long.because.you.know.the rfc.states.that.two.hundred.fifty.five.characters.is.the.max.com";
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, name, GETDNS_RRTYPE_A, NULL,
         "getdns_general_3", &transaction_id, negative_callbackfn),
         GETDNS_RETURN_BAD_DOMAIN_NAME, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_4)
     {
      /*
       *  name = invalid domain (label too long)
       *  expect: GETDNS_RETURN_BAD_DOMAIN_NAME
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
       const char *name = "this.domain.hasalabelwhichexceedsthemaximumdnslabelsizeofsixtythreecharacters.com";
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, name, GETDNS_RRTYPE_A, NULL, 
         "getdns_general_4", &transaction_id, negative_callbackfn),
         GETDNS_RETURN_BAD_DOMAIN_NAME, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_5)
     {
      /*
       *  callbackfn = NULL
       *  expect:  GETDNS_RETURN_GENERIC_ERROR
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "google.com", GETDNS_RRTYPE_A, NULL, 
         "getdns_general_5", &transaction_id, NULL),
         GETDNS_RETURN_GENERIC_ERROR, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_6)
     {
      /*
       *  name = "google.com"
       *  request_type = 0 (minimum valid RRTYPE)
       *  expect: NOERROR/NODATA response:
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount = 0 (number of records in ANSWER section)
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "google.com", 0, NULL,
         "getdns_general_6", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_7)
     {
      /*
       *  name = "google.com"
       *  request_type = 65279 (maximum unassigned RRTYPE)
       *  expect: NOERROR/NODATA response:
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount = 0 (number of records in ANSWER section)
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "google.com", 65279, NULL, 
         "getdns_general_7", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_8)
     {
      /*
       *  name = "google.com"
       *  request_type = GETDNS_RRTYPE_A
       *  expect: NOERROR response with A records
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount >= 1 (number of records in ANSWER section)
       *      and equals number of A records ("type": 1) in "answer" list
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "google.com", GETDNS_RRTYPE_A, NULL, 
         "getdns_general_8", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_9)
     {
      /*
       *  name = "google.com"
       *  request_type = GETDNS_RRTYPE_AAAA
       *  expect: NOERROR response with AAAA records
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount >= 1 (number of records in ANSWER section)
       *      and equals number of AAAA records ("type": 28) in "answer" list
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "google.com", GETDNS_RRTYPE_AAAA, NULL, 
         "getdns_general_9", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_10)
     {
      /*
       *  name = "thisdomainsurelydoesntexist.com"
       *  request_type = GETDNS_RRTYPE_TXT`
       *  expect: NXDOMAIN response with SOA record
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 3
       *    ancount = 0 (number of records in ANSWER section)
       *    nscount = 1 (number of records in AUTHORITY section)
       *      and SOA record ("type": 6) present in "authority" list
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
       const char *name = "thisdomainsurelydoesntexist.com";
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, name, GETDNS_RRTYPE_TXT, NULL, 
         "getdns_general_10", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_11)
     {
      /*
       *  name = "hampster.com"  need to replace this with domain from unbound zone
       *  request_type = GETDNS_RRTYPE_MX
       *  expect: NOERROR/NODATA response:
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount = 0 (number of records in ANSWER section)
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "hampster.com", GETDNS_RRTYPE_MX, NULL, 
         "getdns_general_11", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_12)
     {
      /*
       *  name = "google.com"  need to swap this out for max domain name length with max lable length`
       *  request_type = GETDNS_RRTYPE_A
       *  expect: NOERROR response with A records
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount >= 1 (number of records in ANSWER section)
       *      and equals number of A records ("type": 1) in "answer" list
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "google.com", GETDNS_RRTYPE_A, NULL, 
         "getdns_general_12", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_13)
     {
      /*
       *  name = "75.101.146.66"  need to change this to local unbound data
       *  request_type = GETDNS_RRTYPE_PTR
       *  expect: NOERROR response with PTR record
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount == 1 (number of records in ANSWER section)
       *      and PTR record found ("type": 12) in "answer" list
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "75.101.146.66", GETDNS_RRTYPE_PTR, NULL, 
         "getdns_general_13", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     START_TEST (getdns_general_14)
     {
      /*
       *  name = "2607:f8b0:4006:802::1007"  need to change this to local unbound data
       *  request_type = GETDNS_RRTYPE_PTR
       *  expect: NOERROR response with PTR record
       *    status = GETDNS_RESPSTATUS_GOOD
       *    rcode = 0
       *    ancount == 1 (number of records in ANSWER section)
       *      and PTR record found ("type": 12) in "answer" list
       */
       ASYNCHRONOUS_TEST_DECLARATIONS;
     
       CONTEXT_CREATE;
       EVENT_BASE_CREATE;
       ASSERT_RC(getdns_general(context, "2607:f8b0:4006:802::1007", GETDNS_RRTYPE_PTR, NULL,
         "getdns_general_14", &transaction_id, positive_callbackfn),
         GETDNS_RETURN_GOOD, "Return code from getdns_general()");
       RUN_EVENT_LOOP;
     }
     END_TEST
     
     Suite *
     getdns_general_suite (void)
     {
       Suite *s = suite_create ("getdns_general()");
     
       /* Negative test caseis */
       TCase *tc_neg = tcase_create("Negative");
       tcase_add_test(tc_neg, getdns_general_1);
       tcase_add_test(tc_neg, getdns_general_2);
       tcase_add_test(tc_neg, getdns_general_3);
       tcase_add_test(tc_neg, getdns_general_4);
       tcase_add_test(tc_neg, getdns_general_5);
       suite_add_tcase(s, tc_neg);
     
       /* Positive test cases */
       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_general_6);
       tcase_add_test(tc_pos, getdns_general_7);
       tcase_add_test(tc_pos, getdns_general_8);
       tcase_add_test(tc_pos, getdns_general_9);
       tcase_add_test(tc_pos, getdns_general_10);
       tcase_add_test(tc_pos, getdns_general_11);
       tcase_add_test(tc_pos, getdns_general_12);
       tcase_add_test(tc_pos, getdns_general_13);
       tcase_add_test(tc_pos, getdns_general_14);
       suite_add_tcase(s, tc_pos);
     
       return s;
     }
 
#endif
