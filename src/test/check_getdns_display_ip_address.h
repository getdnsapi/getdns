#ifndef _check_getdns_display_ip_address_h_
#define _check_getdns_display_ip_address_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ D I S P L A Y _ I P _ A D D R E S S   *
     *                                                                        *
     **************************************************************************
    */

    START_TEST (getdns_display_ip_address_1)
    {
     /*
      *  bindata_of_ipv4_or_ipv6_address = NULL
      *  expect:  NULL
      */

      //struct getdns_bindata bindata_of_ipv4_or_ipv6_address = NULL;
      char *ptr = NULL;

      ptr = getdns_display_ip_address(NULL);
      ck_assert_msg(ptr == NULL, "Expected retrieved bindata == NULL, got: %p",
        ptr);
    }
    END_TEST

    START_TEST (getdns_display_ip_address_2)
    {
      /*
      *  bindata_of_ipv4_or_ipv6_address is getdns_bindata but not ip addresses
      *  expect:  Unknown
      */

      char *ptr = NULL;
      struct getdns_bindata bindata_of_ipv4_or_ipv6_address = { 8, (void *)"bindata" };

      ptr = getdns_display_ip_address(&bindata_of_ipv4_or_ipv6_address);

      ck_assert_msg(ptr == NULL, "Expected pointer == NULL, got: %p",
        ptr);  
  
    }
    END_TEST

    START_TEST (getdns_display_ip_address_3)
    {
      /*
       *  Create bindata containing “10.88.30.82"
       * Call getdns_display_ip_address() passing bindata
       *  expect:  10.88.30.82
       */

      char *ptr = NULL;
      struct getdns_bindata bindata_of_ipv4_or_ipv6_address = { 4, (void *)"\x0A\x58\x1E\x52" };

      ptr = getdns_display_ip_address(&bindata_of_ipv4_or_ipv6_address);

      ck_assert_msg(strcmp(ptr, "10.88.30.82") == 0, "Expected pointer == “10.88.30.82”, got: %s",
        ptr);
  
    }
    END_TEST

    START_TEST (getdns_display_ip_address_4)
    {
      /*
       *  Create bindata containing 2607:f8b0:4006:802::1004 
       *  Call getdns_display_ip_address() passing bindata
       *  expect:  2607:f8b0:4006:802::1004
       */

      char *ptr = NULL;
      struct getdns_bindata bindata_of_ipv4_or_ipv6_address = { 16, (void *)"\x26\x07\xf8\xb0\x40\x06\x08\x02\x00\x00\x00\x00\x00\x00\x10\x04" };

      ptr = getdns_display_ip_address(&bindata_of_ipv4_or_ipv6_address);


      ck_assert_msg(strcmp(ptr, "2607:f8b0:4006:802::1004") == 0, "Expected pointer == “2607:f8b0:4006:802::1004”, got: %s",
        ptr);
  
    }
    END_TEST
    
    
    Suite *
    getdns_display_ip_address_suite (void)
    {
      Suite *s = suite_create ("getdns_display_ip_address()");
    
      /* Negative test caseis */
      TCase *tc_neg = tcase_create("Negative");
      tcase_add_test(tc_neg, getdns_display_ip_address_1);
      tcase_add_test(tc_neg, getdns_display_ip_address_2);
      suite_add_tcase(s, tc_neg);
    
      /* Positive test cases */
      TCase *tc_pos = tcase_create("Positive");
      tcase_add_test(tc_pos, getdns_display_ip_address_3);
      tcase_add_test(tc_pos, getdns_display_ip_address_4);
      suite_add_tcase(s, tc_pos);

       return s;

    }

#endif
