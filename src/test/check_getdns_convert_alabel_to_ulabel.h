#ifndef _check_getdns_convert_alabel_to_ulabel_h_
#define _check_getdns_convert_alabel_to_ulabel_h_

    /*
     *************************************************************************************
     *                                                                                   *
     *  T E S T S  F O R  G E T D N S _ C O N V E R T _ A L A B E L _ T O _ U L A B E L  *
     *                                                                                   *
     *************************************************************************************
    */
     
     START_TEST (getdns_convert_alabel_to_ulabel_1)
     {
      /*
       *  ulabel = NULL
       *  expect: GETDNS_RETURN_GENERIC_ERROR
       */
      ulabel = null;

       ASSERT_RC(getdns_convert_alabel_to_ulabel( *ulabel ), 
         GETDNS_RETURN_GENERIC_ERROR, "Return code from getdns_convert_alabel_to_ulabel()");
     }
     END_TEST

     
     Suite *
     getdns_convert_alabel_to_ulabel_suite (void)
     {
       Suite *s = suite_create ("getdns_convert_alabel_to_ulabel()");
     
       /* Negative test caseis */
       TCase *tc_neg = tcase_create("Negative");
       tcase_add_test(tc_neg, getdns_convert_alabel_to_ulabel_1);
       tcase_add_test(tc_neg, getdns_convert_alabel_to_ulabel_2);
       suite_add_tcase(s, tc_neg);
     
       /* Positive test cases */
       TCase *tc_pos = tcase_create("Positive");
       tcase_add_test(tc_pos, getdns_convert_alabel_to_ulabel_3);
       suite_add_tcase(s, tc_pos);
     
       return s;
     }
 
#endif
