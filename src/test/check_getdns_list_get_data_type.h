#ifndef _check_getdns_list_get_data_type_h_
#define _check_getdns_list_get_data_type_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ L I S T _ G E T _ D A T A _ T Y P E   *
     *                                                                        *
     **************************************************************************
    */

    START_TEST (getdns_list_get_data_type_1)
    {
     /*
      *  list = NULL
      *  expect: GETDNS_RETURN_INVALID_PARAMETER
      */
      struct getdns_list *list = NULL;
      size_t index = 0;
      getdns_data_type answer;

      ASSERT_RC(getdns_list_get_data_type(list, index, &answer),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_list_get_data_type()");
    }
    END_TEST

    START_TEST (getdns_list_get_data_type_2)
    {
     /*
      *  index is out of range
      *  Create a list, add an int to it, and then attempt 
      *  to get the data type at index 1
      *  expect: GETDNS_RETURN_NO_SUCH_LIST_ITEM
      */
      struct getdns_list *list = NULL;
      size_t index = 0;
      getdns_data_type answer;

      LIST_CREATE(list);

      ASSERT_RC(getdns_list_set_int(list, index, 1), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_int()");

      index++;
      ASSERT_RC(getdns_list_get_data_type(list, index, &answer),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_list_get_data_type()");

      LIST_DESTROY(list);
    }
    END_TEST

    START_TEST (getdns_list_get_data_type_3)
    {
     /*
      *  answer = NULL
      *  expect: GETDNS_RETURN_INVALID_PARAMETER
      */
      struct getdns_list *list = NULL;
      size_t index = 0;

      LIST_CREATE(list);

      ASSERT_RC(getdns_list_set_int(list, index, 1), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_int()");

      ASSERT_RC(getdns_list_get_data_type(list, index, NULL),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_list_get_data_type()");

      LIST_DESTROY(list);
    }
    END_TEST

    START_TEST (getdns_list_get_data_type_4)
    {
     /*
      *  Create a list (empty) and attempt to get the
      *  data type at index 0.
      *  expect: GETDNS_RETURN_NO_SUCH_LIST_ITEM
      */
      struct getdns_list *list = NULL;
      size_t index = 0;
      getdns_data_type answer;

      LIST_CREATE(list);

      ASSERT_RC(getdns_list_get_data_type(list, index, &answer),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_list_get_data_type()");

      LIST_DESTROY(list);
    }
    END_TEST

    START_TEST (getdns_list_get_data_type_5)
    {
     /*
      *  Create a list, create a dict, set list value at index 0
      *  to the dict, and then get the data type at index 0. 
      *  data type at index 0.
      *  expect: GETDNS_RETURN_GOOD
      *          answer = t_dict (retrieved data type)
      */
      struct getdns_list *list = NULL;
      struct getdns_dict *dict = NULL;
      size_t index = 0;
      getdns_data_type answer;

      LIST_CREATE(list);
      DICT_CREATE(dict);

      ASSERT_RC(getdns_list_set_dict(list, index, dict), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_dict()");

      ASSERT_RC(getdns_list_get_data_type(list, index, &answer),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_get_data_type()");

      ck_assert_msg(answer == t_dict, 
        "Wrong data type, expected t_dict: %d, got %d", t_dict, answer);

      LIST_DESTROY(list);
      DICT_DESTROY(dict);
    }
    END_TEST

    START_TEST (getdns_list_get_data_type_6)
    {
     /*
      *  Create a list, create a second list, set list value at 
      *  index 0 to the second list, and then get the data type 
      *  at index 0. 
      *  expect: GETDNS_RETURN_GOOD
      *          answer = t_list (retrieved data type)
      */
      struct getdns_list *list1 = NULL;
      struct getdns_list *list2 = NULL;
      size_t index = 0;
      getdns_data_type answer;      

      LIST_CREATE(list1);
      LIST_CREATE(list2);

      ASSERT_RC(getdns_list_set_list(list1, index, list2), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_list()");

      ASSERT_RC(getdns_list_get_data_type(list1, index, &answer),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_get_data_type()");

      ck_assert_msg(answer == t_list, 
        "Wrong data type, expected t_list: %d, got %d", t_list, answer);

      LIST_DESTROY(list1);
      LIST_DESTROY(list2);
    }
    END_TEST

    START_TEST (getdns_list_get_data_type_7)
    {
     /*
      *  Create a list, create some bindata, set list value at 
      *  index 0 to the bindata, and then get the data type at
      *  index 0. 
      *  expect: GETDNS_RETURN_GOOD
      *          answer = t_bindata (retrieved data type)
      */
      struct getdns_list *list = NULL;
      struct getdns_bindata bindata = { 8, (void *)"bindata" };
      size_t index = 0;
      getdns_data_type answer;

      LIST_CREATE(list);

      ASSERT_RC(getdns_list_set_bindata(list, index, &bindata), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_bindata()");

      ASSERT_RC(getdns_list_get_data_type(list, index, &answer),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_get_data_type()");

      ck_assert_msg(answer == t_bindata, 
        "Wrong data type, expected t_bindata: %d, got %d", t_bindata, answer);

      LIST_DESTROY(list);
    }
    END_TEST

    START_TEST (getdns_list_get_data_type_8)
    {
     /*
      *  Create a list, set list value at index 0 to 100 (int),
      *  and then get the data type at index 0. 
      *  expect: GETDNS_RETURN_GOOD
      *          answer = t_int (retrieved data type)
      */
      struct getdns_list *list = NULL;
      size_t index = 0;
      getdns_data_type answer;

      LIST_CREATE(list);

      ASSERT_RC(getdns_list_set_int(list, index, 100), GETDNS_RETURN_GOOD,
        "Return code from getdns_list_set_int()");

      ASSERT_RC(getdns_list_get_data_type(list, index, &answer),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_get_data_type()");

      ck_assert_msg(answer == t_int, 
        "Wrong data type, expected t_int: %d, got %d", t_int, answer);

      LIST_DESTROY(list);
    }
    END_TEST

    Suite *
    getdns_list_get_data_type_suite (void)
    {
      Suite *s = suite_create ("getdns_list_get_data_type()");

      /* Negative test caseis */
      TCase *tc_neg = tcase_create("Negative");
      tcase_add_test(tc_neg, getdns_list_get_data_type_1);
      tcase_add_test(tc_neg, getdns_list_get_data_type_2);
      tcase_add_test(tc_neg, getdns_list_get_data_type_3);
      suite_add_tcase(s, tc_neg);

      /* Positive test cases */
      TCase *tc_pos = tcase_create("Positive");
      tcase_add_test(tc_pos, getdns_list_get_data_type_4);
      tcase_add_test(tc_pos, getdns_list_get_data_type_5);
      tcase_add_test(tc_pos, getdns_list_get_data_type_6);
      tcase_add_test(tc_pos, getdns_list_get_data_type_7);
      tcase_add_test(tc_pos, getdns_list_get_data_type_8);
      suite_add_tcase(s, tc_pos);

      return s;
    }

#endif
