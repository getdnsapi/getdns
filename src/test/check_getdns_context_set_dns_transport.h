#ifndef _check_getdns_context_set_dns_transport_h_
#define _check_getdns_context_set_dns_transport_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ C O N T E X T _ S E T _ C O N T E X T _ U P D A T E _ C A L L B A C K *
     *                                                                        *
     **************************************************************************
    */

    START_TEST (getdns_context_set_dns_transport_1)
    {
     /*
      *  context is NULL
      *  expect:  GETDNS_RETURN_BAD_CONTEXT
      */

      struct getdns_context *context = NULL;
      uint16_t value = 302;

      ASSERT_RC(getdns_context_set_dns_transport(context, value),
        GETDNS_RETURN_BAD_CONTEXT, "Return code from getdns_context_set_dns_transport()");
        
    }
    END_TEST

    START_TEST (getdns_context_set_dns_transport_2)
    {
     /*
      *  value is an undefined transport value
      *  expect: GETDNS_RETURN_CONTEXT_UPDATE_FAIL
      */

      struct getdns_context *context = NULL;
      //uint16_t value = 233;
      CONTEXT_CREATE(TRUE);


      ASSERT_RC(getdns_context_set_dns_transport(context, 233),
        GETDNS_RETURN_CONTEXT_UPDATE_FAIL, "Return code from getdns_context_set_dns_transport()");

      CONTEXT_DESTROY;
        
    }
    END_TEST

     START_TEST (getdns_context_set_dns_transport_3)
     {
       /*
       *  Call getdns_context_set_dns_transport() with value = GETDNS_CONTEXT_UDP_ONLY
       *  Define a callback routine for context changes and call getdns_context_set_context_update_callback() so that it gets called when there are context changes
       *  getdns_context_set_resolution_type() to GETDNS_CONTEXT_STUB
       *  expect:  GETDNS_CONTEXT_CODE_RESOLUTION_TYPE
       */
       struct getdns_context *context = NULL;
       struct getdns_dict *response = NULL;
       uint32_t ancount;
       uint32_t arcount;
       uint32_t nscount;
       uint32_t tcp_ancount;
       uint32_t tcp_arcount;
       uint32_t tcp_nscount;
       int udp_sum;
       int tcp_sum;
       
        CONTEXT_CREATE(TRUE);


       ASSERT_RC(getdns_context_set_dns_transport(context, GETDNS_CONTEXT_UDP_ONLY),
         GETDNS_RETURN_GOOD, "Return code from getdns_context_set_dns_transport()");   
     

       ASSERT_RC(getdns_general_sync(context, "google.com", 255, NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_general_sync()");

       EXTRACT_RESPONSE;


      ASSERT_RC(getdns_dict_get_int(ex_response.header, "ancount", &ancount),
        GETDNS_RETURN_GOOD, "Failed to extract \"nscount\"");

      ASSERT_RC(getdns_dict_get_int(ex_response.header, "arcount", &arcount),
        GETDNS_RETURN_GOOD, "Failed to extract \"nscount\"");

      ASSERT_RC(getdns_dict_get_int(ex_response.header, "nscount", &nscount),
        GETDNS_RETURN_GOOD, "Failed to extract \"nscount\"");

       printf("the resp is %s\n", getdns_pretty_print_dict(response));
       printf("the ancount is %d\n", ancount);
       printf("the arcount is %d\n", arcount);
       printf("the nscount is %d\n", nscount);
       udp_sum = ancount + arcount + nscount;
       printf("the udp_sum is %d\n", udp_sum);

       //tcp count
       ASSERT_RC(getdns_context_set_dns_transport(context, GETDNS_CONTEXT_TCP_ONLY),
         GETDNS_RETURN_GOOD, "Return code from getdns_context_set_dns_transport()");   
     

       ASSERT_RC(getdns_general_sync(context, "google.com", 255, NULL, &response), 
         GETDNS_RETURN_GOOD, "Return code from getdns_general_sync()");

       struct extracted_response ex_response1;	
       extract_response(response, &ex_response1);

       ASSERT_RC(getdns_dict_get_int(ex_response1.header, "ancount", &tcp_ancount),
        GETDNS_RETURN_GOOD, "Failed to extract \"nscount\"");

      ASSERT_RC(getdns_dict_get_int(ex_response1.header, "arcount", &tcp_arcount),
        GETDNS_RETURN_GOOD, "Failed to extract \"nscount\"");

      ASSERT_RC(getdns_dict_get_int(ex_response1.header, "nscount", &tcp_nscount),
        GETDNS_RETURN_GOOD, "Failed to extract \"nscount\"");

       printf("the resp is %s\n", getdns_pretty_print_dict(response));

      printf("the tcp_ancount is %d\n", tcp_ancount);
      printf("the tcp_arcount is %d\n", tcp_arcount);
      printf("the tcp_nscount is %d\n", tcp_nscount);
      tcp_sum = tcp_ancount + tcp_arcount + tcp_nscount;
      printf("the tcp_sum is %d\n", udp_sum);

      CONTEXT_DESTROY;

       
  
     }
     END_TEST

    

    
    
    Suite *
    getdns_context_set_dns_transport_suite (void)
    {
      Suite *s = suite_create ("getdns_context_set_dns_transport()");
    
      /* Negative test caseis */
      TCase *tc_neg = tcase_create("Negative");
      tcase_add_test(tc_neg, getdns_context_set_dns_transport_1);
      tcase_add_test(tc_neg, getdns_context_set_dns_transport_2);
      suite_add_tcase(s, tc_neg);
    
      /* Positive test cases */
       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_context_set_dns_transport_3);
      
       suite_add_tcase(s, tc_pos);

       return s;

    }

#endif
