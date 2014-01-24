#ifndef _check_getdns_list_get_dict_h_
#define _check_getdns_list_get_dict_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ L I S T _ G E T _ D I C T   *
     *                                                                        *
     **************************************************************************
    */

    START_TEST (getdns_list_get_dict_1)
    {
     /*
      *  list = NULL
      *  expect: GETDNS_RETURN_INVALID_PARAMETER
      */
      struct getdns_list *list = NULL;
      size_t index = 0;
      struct getdns_dict *answer = NULL;

      ASSERT_RC(getdns_list_get_dict(list, index, &answer),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_list_get_dict()");
    }
    END_TEST

    START_TEST (getdns_list_get_dict_2)
    {
     /*
      *  index is out of range
      *  Create a list, add an dict to it, and then attempt 
      *  expect: GETDNS_RETURN_INVALID_PARAMETER
      */
      struct getdns_list *list = NULL;
      size_t index = 0;
      struct getdns_dict *answer = NULL;

      LIST_CREATE(list);
      DICT_CREATE(answer);

      ASSERT_RC(getdns_list_set_int(list, index, 1), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_int()");

      index++;
      ASSERT_RC(getdns_list_get_dict(list, index, NULL),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_list_get_dict()");


      LIST_DESTROY(list);
      DICT_DESTROY(answer);
    }
    END_TEST

    START_TEST (getdns_list_get_dict_3)
    {
     /*
      *  data type at index is not dict 
      *  create a list
      *  expect: GETDNS_RETURN_WRONG_TYPE_REQUESTED
      */
      struct getdns_list *list = NULL;
      struct getdns_dict *answer = NULL;
      size_t index = 0;

      LIST_CREATE(list);
      DICT_CREATE(answer);

      ASSERT_RC(getdns_list_set_int(list, index, 10), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_int()");
      
      ASSERT_RC(getdns_list_get_dict(list, index, &answer),
        GETDNS_RETURN_WRONG_TYPE_REQUESTED, "Return code from getdns_list_get_dict()");

      LIST_DESTROY(list);
      DICT_DESTROY(answer);
    }
    END_TEST


      START_TEST (getdns_list_get_dict_4)
    {
     /*
      *  answer = NULL
      *  expect: GETDNS_RETURN_INVALID_PARAMETER
      */
      struct getdns_list *list = NULL;
      size_t index = 0;

      ASSERT_RC(getdns_list_get_dict(list, index, NULL),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_list_get_dict()");
    }
    END_TEST

   



    START_TEST (getdns_list_get_dict_5)
    {
     /*
      *  create a list
      *  Create a dict with one int (name = "ten", value = 10)
      *  Call getdns_dict_get_list() with name = "ten"
      *  expect:  GETDNS_RETURN_WRONG_TYPE_REQUESTED
      */
      struct getdns_dict *dict = NULL;
      size_t index = 0;
      struct getdns_dict *answer = NULL;

      struct getdns_list *list = NULL;
      uint32_t value;
      
      LIST_CREATE(list);
      DICT_CREATE(dict);

      ASSERT_RC(getdns_dict_set_int(dict, "ten", 10),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");

      ASSERT_RC(getdns_list_set_dict(list, index, dict), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_dict()");

      ASSERT_RC(getdns_list_get_dict(list, index, &answer),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_get_dict()");

      ASSERT_RC(getdns_dict_get_int(answer, "ten", &value),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_int()");

      ck_assert_msg(value == 10, "Expected retrieved int == 10, got: %d",
        value);


      LIST_DESTROY(list);
      DICT_DESTROY(dict);
    }
    END_TEST
    

    

    
    Suite *
    getdns_list_get_dict_suite (void)
    {
      Suite *s = suite_create ("getdns_list_get_dict()");

      /* Negative test caseis */
      TCase *tc_neg = tcase_create("Negative");
      tcase_add_test(tc_neg, getdns_list_get_dict_1);
      tcase_add_test(tc_neg, getdns_list_get_dict_2);
      tcase_add_test(tc_neg, getdns_list_get_dict_3);
      tcase_add_test(tc_neg, getdns_list_get_dict_4);
      suite_add_tcase(s, tc_neg);

      /* Positive test cases */
       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_list_get_dict_5);
       suite_add_tcase(s, tc_pos);

      return s;
    }

#endif
