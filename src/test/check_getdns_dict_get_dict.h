#ifndef _check_getdns_dict_get_dict_h_
#define _check_getdns_dict_get_dict_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ D I C T _ G E T _ D I C T             *
     *                                                                        *
     **************************************************************************
    */

    START_TEST (getdns_dict_get_dict_1)
    {
     /*
      *  this_dict = NULL
      *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_dict *answer = NULL;

      ASSERT_RC(getdns_dict_get_dict(this_dict, "key", &answer),
        GETDNS_RETURN_NO_SUCH_DICT_NAME, "Return code from getdns_dict_get_dict()");

    }
    END_TEST

    START_TEST (getdns_dict_get_dict_2)
    {
     /*
      *  name = NULL
      *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_dict *second_dict = NULL;
      struct getdns_dict *answer = NULL;

      DICT_CREATE(this_dict);
      DICT_CREATE(second_dict);
      ASSERT_RC(getdns_dict_set_dict(this_dict, "dict", second_dict),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_dict()");

      ASSERT_RC(getdns_dict_get_dict(this_dict, NULL, &answer),
        GETDNS_RETURN_NO_SUCH_DICT_NAME, "Return code from getdns_dict_get_dict()");

      DICT_DESTROY(this_dict);
      DICT_DESTROY(second_dict);
    }
    END_TEST
    
    START_TEST (getdns_dict_get_dict_3)
    {
     /*
      *  name does not exist in dict
      *  Create a dict
      *  Create a second dict with three ints ("ten" = 10, "eleven" = 11, "twelve" = 12)
      *  Add the second dict to the first dict as name = "numbers"
      *  Call getdns_dict_get_dict() against the first dict with name = "letters"
      *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_dict *second_dict = NULL;
      char *keys[3] = { "ten", "eleven", "twelve" };
      uint32_t values[3] = { 10, 11, 12 };
      int i;
      struct getdns_dict *answer = NULL;

      DICT_CREATE(this_dict);
      DICT_CREATE(second_dict);

      for(i = 0; i < 3; i++)
      {
        ASSERT_RC(getdns_dict_set_int(second_dict, keys[i], values[i]), 
          GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");
      }

      ASSERT_RC(getdns_dict_set_dict(this_dict, "numbers", second_dict),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_dict()");

      ASSERT_RC(getdns_dict_get_dict(this_dict, "letters", &answer),
        GETDNS_RETURN_NO_SUCH_DICT_NAME, "Return code from getdns_dict_get_dict()");

      DICT_DESTROY(this_dict);
      DICT_DESTROY(second_dict);
    }
    END_TEST
    
    START_TEST (getdns_dict_get_dict_4)
    {
     /*
      *  data type at name is not a dict
      *  Create a dict with one int (name = "ten", value = 10)
      *  Call getdns_dict_get_dict() with name = "ten"
      *  expect:  GETDNS_RETURN_WRONG_TYPE_REQUESTED
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_dict *answer = NULL;

      DICT_CREATE(this_dict);

      ASSERT_RC(getdns_dict_set_int(this_dict, "ten", 10), 
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");

      ASSERT_RC(getdns_dict_get_dict(this_dict, "ten", &answer),
        GETDNS_RETURN_WRONG_TYPE_REQUESTED, "Return code from getdns_dict_get_dict()");

      DICT_DESTROY(this_dict);
    }
    END_TEST
    
    START_TEST (getdns_dict_get_dict_5)
    {
     /*
      *  answer = NULL
      *  expect: GETDNS_RETURN_NO_SUCH_DICT_NAME
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_dict *second_dict = NULL;

      DICT_CREATE(this_dict);
      DICT_CREATE(second_dict);

      ASSERT_RC(getdns_dict_set_dict(this_dict, "dict", second_dict),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_dict()");

      ASSERT_RC(getdns_dict_get_dict(this_dict, "dict", NULL),
        GETDNS_RETURN_NO_SUCH_DICT_NAME, "Return code from getdns_dict_get_dict()");

      DICT_DESTROY(this_dict);
      DICT_DESTROY(second_dict);
    }
    END_TEST
    
    START_TEST (getdns_dict_get_dict_6)
    {
     /*
      *  successful get dict
      *  Create a dict
      *  Create a second dict with three ints ("ten" = 10, "eleven" = 11, "twelve" = 12)
      *  Add the second dict to the first dict as name = "numbers"
      *  Call getdns_dict_get_dict() against the first dict for name = "numbers"
      *  Call getdns_dict_get_names() against the retrieved "numbers" dict to get a list of names
      *  Call getdns_list_get_length() against the returned list to set a loop counter
      *  Iterate through the names in the list and add the int value from each key to sum
      *  expect:  sum == 33
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_dict *second_dict = NULL;
      char *keys[3] = { "ten", "eleven", "twelve" };
      uint32_t values[3] = { 10, 11, 12 };
      size_t i;
      uint32_t sum_of_values = 0;
      struct getdns_dict *answer = NULL;
      struct getdns_list *names = NULL;
      size_t length;
      struct getdns_bindata *bindata = NULL;
      uint32_t value;
      uint32_t sum = 0;

      DICT_CREATE(this_dict);
      DICT_CREATE(second_dict);

      for(i = 0; i < 3; i++)
      {
        ASSERT_RC(getdns_dict_set_int(second_dict, keys[i], values[i]), 
          GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");
        sum_of_values += values[i];
      }

      ASSERT_RC(getdns_dict_set_dict(this_dict, "numbers", second_dict),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_dict()");

      ASSERT_RC(getdns_dict_get_dict(this_dict, "numbers", &answer),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_dict()");

      ASSERT_RC(getdns_dict_get_names(answer, &names),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_names()");

      ASSERT_RC(getdns_list_get_length(names, &length),
        GETDNS_RETURN_GOOD, "Return code from getdns_list_get_length()");

      for(i = 0; i < length; i++)
      {
        ASSERT_RC(getdns_list_get_bindata(names, i, &bindata),
          GETDNS_RETURN_GOOD, "Return code from getdns_list_get_bindata()");
        ASSERT_RC(getdns_dict_get_int(answer, (char *)bindata->data, &value),
          GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_int()");
        sum += value;
      }

      ck_assert_msg(sum == sum_of_values, "Sum of int values in dict should == %d, got: %d",
        sum_of_values, sum);

      DICT_DESTROY(this_dict);
      DICT_DESTROY(second_dict);
    }
    END_TEST
    
    Suite *
    getdns_dict_get_dict_suite (void)
    {
      Suite *s = suite_create ("getdns_dict_get_dict()");
    
      /* Negative test caseis */
      TCase *tc_neg = tcase_create("Negative");
      tcase_add_test(tc_neg, getdns_dict_get_dict_1);
      tcase_add_test(tc_neg, getdns_dict_get_dict_2);
      tcase_add_test(tc_neg, getdns_dict_get_dict_3);
      tcase_add_test(tc_neg, getdns_dict_get_dict_4);
      tcase_add_test(tc_neg, getdns_dict_get_dict_5);
      suite_add_tcase(s, tc_neg);
    
      /* Positive test cases */
      TCase *tc_pos = tcase_create("Positive");
      tcase_add_test(tc_pos, getdns_dict_get_dict_6);
      suite_add_tcase(s, tc_pos);
    
      return s;
    }

#endif
