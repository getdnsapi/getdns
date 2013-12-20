#ifndef _check_getdns_list_get_length_h_
#define _check_getdns_list_get_length_h_

    START_TEST (getdns_list_get_length_1)
    {
     /*
      *  list = NULL
      *  expect = GETDNS_RETURN_NO_SUCH_LIST_ITEM
      */
      struct getdns_list *list = NULL;
      size_t length;

      ASSERT_RC(getdns_list_get_length(list, &length),
        GETDNS_RETURN_NO_SUCH_LIST_ITEM, "Return code from getdns_list_get_length()");

    }
    END_TEST
    
    START_TEST (getdns_list_get_length_2)
    {
     /*
      *  answer = NULL
      *  expect: GETDNS_RETURN_NO_SUCH_LIST_ITEM
      */
      struct getdns_list *list = NULL;

      LIST_CREATE(list);

      ASSERT_RC(getdns_list_get_length(list, NULL),
        GETDNS_RETURN_NO_SUCH_LIST_ITEM, "Return code from getdns_list_get_length()");

    }
    END_TEST
    
    START_TEST (getdns_list_get_length_3)
    {
     /*
      *  Create a list, add 3 ints to it, get the length.
      *  expect: GETDNS_RETURN_GOOD
      *          length = 3
      */
      struct getdns_list *list = NULL;
      size_t i;
      size_t length;

      LIST_CREATE(list);

      for(i = 0; i < 3; i++)
      {
        ASSERT_RC(getdns_list_set_int(list, i, i), GETDNS_RETURN_GOOD,
          "Return code from getdns_list_set_int()");
      }

      ASSERT_RC(getdns_list_get_length(list, &length),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_get_length()");

      ck_assert_msg(length == 3, "Expected length == 3, got %d", length);

    }
    END_TEST
    
    START_TEST (getdns_list_get_length_4)
    {
     /*
      *  Create a list (empty) and get the length
      *  expect: GETDNS_RETURN_GOOD
      *          length = 3
      */
      struct getdns_list *list = NULL;
      size_t length;

      LIST_CREATE(list);

      ASSERT_RC(getdns_list_get_length(list, &length),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_get_length()");

      ck_assert_msg(length == 0, "Expected length == 3, got %d", length);
    
    }
    END_TEST
    
    Suite *
    getdns_list_get_length_suite (void)
    {
      Suite *s = suite_create ("getdns_list_get_length()");
    
      /* Negative test caseis */
      TCase *tc_neg = tcase_create("Negative");
      tcase_add_test(tc_neg, getdns_list_get_length_1);
      tcase_add_test(tc_neg, getdns_list_get_length_2);
      suite_add_tcase(s, tc_neg);
    
      /* Positive test cases */
      TCase *tc_pos = tcase_create("Positive");
      tcase_add_test(tc_pos, getdns_list_get_length_3);
      tcase_add_test(tc_pos, getdns_list_get_length_4);
      suite_add_tcase(s, tc_pos);
    
      return s;
    }

#endif
