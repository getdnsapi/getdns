#ifndef _check_getdns_dict_set_bindata_h_
#define _check_getdns_dict_set_bindata_h_

    /*
     **************************************************************************
     *                                                                        *
     *  T E S T S  F O R  G E T D N S _ D I C T _ S E T _ B I N D A T A       *
     *                                                                        *
     **************************************************************************
    */

    START_TEST (getdns_dict_set_bindata_1)
    {
     /*
      *  this_dict = NULL
      *  expect:  GETDNS_RETURN_NO_SUCH_DICT_NAME
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_bindata bindata = { 8, (void *)"bindata" };

      ASSERT_RC(getdns_dict_set_bindata(this_dict, "key", &bindata),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_dict_set_bindata()");

    }
    END_TEST

    START_TEST (getdns_dict_set_bindata_2)
    {
     /*
      *  name = NULL
      *  expect:  GETDNS_RETURN_INVALID_PARAMETER
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_bindata bindata = { 8, (void *)"bindata" };

      DICT_CREATE(this_dict);

      ASSERT_RC(getdns_dict_set_bindata(this_dict, NULL, &bindata),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_dict_set_bindata()");

      DICT_DESTROY(this_dict);
    }
    END_TEST

    START_TEST (getdns_dict_set_bindata_3)
    {
     /*
      *  child_bindata = NULL
      *  expect:  GETDNS_RETURN_INVALID_PARAMETER
      */
      struct getdns_dict *this_dict = NULL;

      DICT_CREATE(this_dict);

      ASSERT_RC(getdns_dict_set_bindata(this_dict, "bindata", NULL),
        GETDNS_RETURN_INVALID_PARAMETER, "Return code from getdns_dict_set_bindata()");

      DICT_DESTROY(this_dict);
    }
    END_TEST
    
    START_TEST (getdns_dict_set_bindata_4)
    {
     /*
      *  name already exists in dict
      *  Create a dict
      *  Add bindata to the dict (name = "bindata", value = { 8, "bindata" })
      *  Add bindata to the dict (name = "bindata", value = { 15, "second_bindata" })
      *  Call getdns_dict_get_bindata() with name = "bindata"
      *  expect:  GETDNS_RETURN_GOOD (all functions)
      *           bindata retrieved = "second_bindata"
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_bindata bindata = { 8, (void *)"bindata" };
      struct getdns_bindata second_bindata = { 15, (void *)"second_bindata" };
      struct getdns_bindata *retrieved_bindata = NULL;

      DICT_CREATE(this_dict);

      ASSERT_RC(getdns_dict_set_bindata(this_dict, "bindata", &bindata), 
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

      ASSERT_RC(getdns_dict_set_bindata(this_dict, "bindata", &second_bindata),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

      ASSERT_RC(getdns_dict_get_bindata(this_dict, "bindata", &retrieved_bindata),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_bindata()");

      ck_assert_msg(retrieved_bindata->size, second_bindata.size,
        "Expected retrieved bindata size == %d, got: %d",
        second_bindata.size, retrieved_bindata->size);

      ck_assert_msg(strcmp((char *)retrieved_bindata->data, (char *)second_bindata.data) == 0,
        "Expected retrieved bindata to be \"%s\", got: \"%s\"",
        (char *)second_bindata.data, (char *)retrieved_bindata->data);

      DICT_DESTROY(this_dict);
    }
    END_TEST
    
    START_TEST (getdns_dict_set_bindata_5)
    {
     /*
      *  name already exists in dict, changing data type
      *  Create a dict
      *  Add an int to the dict (name = "int", value = 100)
      *  Add bindata to the dict (name = "int", value = { 8, "bindata" })
      *  Call getdns_dict_get_bindata() against the dict with name = "int"
      *  expect:  GETDNS_RETURN_GOOD (all functions)
      *           retrieved bindata should == "bindata"
      */
      struct getdns_dict *this_dict = NULL;
      struct getdns_bindata bindata = { 8, (void *)"bindata" };
      struct getdns_bindata *retrieved_bindata = NULL;

      DICT_CREATE(this_dict);

      ASSERT_RC(getdns_dict_set_int(this_dict, "int", 100),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_int()");

      ASSERT_RC(getdns_dict_set_bindata(this_dict, "int", &bindata),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_set_bindata()");

      ASSERT_RC(getdns_dict_get_bindata(this_dict, "int", &retrieved_bindata),
        GETDNS_RETURN_GOOD, "Return code from getdns_dict_get_bindata()");

      ck_assert_msg(retrieved_bindata->size == bindata.size, 
        "Expected retrieved bindata size == %d, got: %d",
        bindata.size, retrieved_bindata->size);

      ck_assert_msg(strcmp((char *)retrieved_bindata->data, (char *)bindata.data) == 0, 
        "Expected bindata data to be \"%s\", got: \"%s\"",
        (char *)bindata.data, (char *)retrieved_bindata->data);

      DICT_DESTROY(this_dict);
    }
    END_TEST
    
    Suite *
    getdns_dict_set_bindata_suite (void)
    {
      Suite *s = suite_create ("getdns_dict_set_bindata()");
    
      /* Negative test caseis */
      TCase *tc_neg = tcase_create("Negative");
      tcase_add_test(tc_neg, getdns_dict_set_bindata_1);
      tcase_add_test(tc_neg, getdns_dict_set_bindata_2);
      tcase_add_test(tc_neg, getdns_dict_set_bindata_3);
      suite_add_tcase(s, tc_neg);
    
      /* Positive test cases */
      TCase *tc_pos = tcase_create("Positive");
      tcase_add_test(tc_pos, getdns_dict_set_bindata_4);
      tcase_add_test(tc_pos, getdns_dict_set_bindata_5);
      suite_add_tcase(s, tc_pos);
    
      return s;
    }

#endif
