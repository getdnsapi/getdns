#ifndef _check_getdns_dict_set_dict_h_
#define _check_getdns_dict_set_dict_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ D I C T _ S E T _ D I C T             *
     *                                                                        *
     **************************************************************************
    */

    START_TEST (getdns_dict_set_dict_1)
    {
     /*
      *  this_dict = NULL
      *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_dict *child_dict = NULL;

      DICT_CREATE(child_dict);
      ASSERT_RC(getdns_dict_set_dict(this_dict, "dict", child_dict),
        GETDNS_RETURN_NO_SUCH_DICT_NAME, "Return code from getdns_dict_set_dict()");
      DICT_DESTROY(child_dict);

    }
    END_TEST

    START_TEST (getdns_dict_set_dict_2)
    {
     /*
      *  child_dict = NULL
      *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_dict *child_dict = NULL;

      DICT_CREATE(this_dict);
      ASSERT_RC(getdns_dict_set_dict(this_dict, "dict", child_dict),
        GETDNS_RETURN_GENERIC_ERROR, "Return code from getdns_dict_set_dict()");

      DICT_DESTROY(this_dict);
    }
    END_TEST
    
    START_TEST (getdns_dict_set_dict_3)
    {
     /*
      *  name already exists in dict
      *  Create a dict
      *  Create a second dict containing name = "int" with value = 100
      *  Add the second dict to the first dict as name = "dict"
      *  Create a third dict containing name = "int" with value = 101
      *  Add the third dict to the first dict as name = "dict"
      *  Call getdns_dict_get_dict() against the first dict with name = "dict"
      *  Call getdns_dict_get_int() against the retrieved dict for name = "int"
      *  expect:  GETDNS_RETURN_GOOD (all functions)
      *           retrieved int should = 101
      */
      struct getdns_dict *first_dict = NULL;
      struct getdns_dict *second_dict = NULL;
      struct getdns_dict *third_dict = NULL;
      struct getdns_dict *answer = NULL;
      uint32_t retrieved_int;

      DICT_CREATE(first_dict);

      DICT_CREATE(second_dict);
      ASSERT_RC(getdns_dict_set_int(second_dict, "int", 100), 
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");
      ASSERT_RC(getdns_dict_set_dict(first_dict, "dict", second_dict),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_dict()");

      DICT_CREATE(third_dict);
      ASSERT_RC(getdns_dict_set_int(third_dict, "int", 101), 
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");
      ASSERT_RC(getdns_dict_set_dict(first_dict, "dict", third_dict),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_dict()");

      ASSERT_RC(getdns_dict_get_dict(first_dict, "dict", &answer),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_dict()");

      ASSERT_RC(getdns_dict_get_int(answer, "int", &retrieved_int),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_int()");

      ck_assert_msg(retrieved_int == 101, "Exepected retrieved int == 101, got: %d", 
        retrieved_int);

      DICT_DESTROY(first_dict);
      DICT_DESTROY(second_dict);
      DICT_DESTROY(third_dict);
    }
    END_TEST
    
    START_TEST (getdns_dict_set_dict_4)
    {
     /*
      *  name already exists in dict, changing data type
      *  Create a dict
      *  Create a list
      *  Set list value at index 0 to int 100
      *  Add the list to the dict as name = "list"
      *  Create a second dict
      *  Add an int to the second dict with name = "int", value = 101
      *  Add the second dict to the first dict as name = "list"
      *  Call getdns_dict_get_dict to retrieve the second dict
      *  Call getdns_dict_get_int with name = "int"
      *  expect:  GETDNS_RETURN_GOOD (all functions)
      *           retrieved int should = 101
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_list *list = NULL;
      struct getdns_dict *second_dict = NULL;
      struct getdns_dict *answer = NULL;
      uint32_t retrieved_int;

      DICT_CREATE(this_dict);

      LIST_CREATE(list);
      ASSERT_RC(getdns_list_set_int(list, 0, 100),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_set_int()");

      ASSERT_RC(getdns_dict_set_list(this_dict, "list", list),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_list()");

      DICT_CREATE(second_dict);
      ASSERT_RC(getdns_dict_set_int(second_dict, "int", 101),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");
      ASSERT_RC(getdns_dict_set_dict(this_dict, "list", second_dict),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_dict()");

      ASSERT_RC(getdns_dict_get_dict(this_dict, "list", &answer),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_dict()");
      ASSERT_RC(getdns_dict_get_int(answer, "int", &retrieved_int),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_int()");

      ck_assert_msg(retrieved_int == 101, "Exepected retrieved int == 101, got: %d", 
        retrieved_int);

      DICT_DESTROY(this_dict);
      LIST_DESTROY(list);
      DICT_DESTROY(second_dict);
    }
    END_TEST
    
    Suite *
    getdns_dict_set_dict_suite (void)
    {
      Suite *s = suite_create ("getdns_dict_set_dict()");
    
      /* Negative test caseis */
      TCase *tc_neg = tcase_create("Negative");
      tcase_add_test(tc_neg, getdns_dict_set_dict_1);
      tcase_add_test(tc_neg, getdns_dict_set_dict_2);
      suite_add_tcase(s, tc_neg);
    
      /* Positive test cases */
      TCase *tc_pos = tcase_create("Positive");
      tcase_add_test(tc_pos, getdns_dict_set_dict_3);
      tcase_add_test(tc_pos, getdns_dict_set_dict_4);
      suite_add_tcase(s, tc_pos);
    
      return s;
    }

#endif
