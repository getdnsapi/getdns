#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <check.h>
#include <getdns/getdns.h>
#include "check_getdns_libevent.h"
#include "check_getdns_common.h"
#include "check_getdns_general.h"
#include "check_getdns_general_sync.h"
#include "check_getdns_context_create.h"
#include "check_getdns_context_destroy.h"
#include "check_getdns_cancel_callback.h"
#include "check_getdns_address_sync.h"
#include "check_getdns_list_get_length.h"
#include "check_getdns_list_get_data_type.h"
#include "check_getdns_dict_get_names.h"

int
main (void)
{
  int number_failed;
  SRunner *sr ;

  Suite *getdns_general_suite(void);
  Suite *getdns_general_sync_suite(void);
  Suite *getdns_address_sync_suite(void);
  Suite *getdns_context_create_suite(void);
  Suite *getdns_context_destroy_suite(void);
  Suite *getdns_cancel_callback_suite(void);
  Suite *getdns_list_get_length_suite(void);
  Suite *getdns_list_get_data_type_suite(void);
  Suite *getdns_dict_get_names_suite(void);

  sr = srunner_create(getdns_general_suite());
  srunner_add_suite(sr, getdns_general_sync_suite());
  srunner_add_suite(sr, getdns_address_sync_suite());
  srunner_add_suite(sr, getdns_context_create_suite());
  srunner_add_suite(sr, getdns_context_destroy_suite());
  srunner_add_suite(sr, getdns_cancel_callback_suite());
  srunner_add_suite(sr, getdns_list_get_length_suite());
  srunner_add_suite(sr, getdns_list_get_data_type_suite());
  srunner_add_suite(sr, getdns_dict_get_names_suite());

  srunner_set_log(sr, "check_getdns.log");
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
