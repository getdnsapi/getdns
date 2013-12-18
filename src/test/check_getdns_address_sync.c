#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <check.h>
#include <getdns/getdns.h>

#define TRUE 1
#define FALSE 0
#define MAXLEN 200

struct extracted_response {
  uint32_t top_answer_type;
  struct getdns_bindata *top_canonical_name;
  struct getdns_list *just_address_answers;
  struct getdns_list *replies_full;
  struct getdns_list *replies_tree;
  struct getdns_dict *replies_tree_sub_dict;
  struct getdns_list *additional;
  struct getdns_list *answer;
  uint32_t answer_type;
  struct getdns_list *authority;
  struct getdns_bindata *canonical_name;
  struct getdns_dict *header;
  struct getdns_dict *question;
  uint32_t status;
};

/*
 *  The STANDARD_TEST_DECLARATIONS macro defines
 *  the standard variable definitions most tests
 *  will need.
 *
 */
#define STANDARD_TEST_DECLARATIONS		\
  struct getdns_context *context = NULL;	\
  struct getdns_dict *response = NULL; 		\
  size_t buflen = MAXLEN;			\
  char error_string[MAXLEN];
  
/*
 *  The ASSERT_RC macro is used to assert
 *  whether the return code from the last
 *  getdns API call is what was expected.
 */
#define ASSERT_RC(rc, expected_rc, prefix)		\
  getdns_strerror(rc, error_string, buflen);		\
  ck_assert_msg(rc == expected_rc,			\
    "%s: expecting %s: %d, but received: %d: %s",	\
    prefix, #expected_rc, expected_rc, rc, error_string);

/*
 *  The CONTEXT_CREATE macro is used to			\
 *  create a context and assert the proper		\
 *  return code is returned.				\
 */							\
#define CONTEXT_CREATE					\
  ASSERT_RC(getdns_context_create(&context, TRUE),	\
    GETDNS_RETURN_GOOD, 				\
    "Return code from getdns_context_create()");

/*							\
 *  The process_response macro declares the		\
 *  variables needed to house the response and		\
 *  calls the function that extracts it.		\
 */							\
#define EXTRACT_RESPONSE				\
  struct extracted_response ex_response;		\
  extract_response(response, &ex_response);
 
void extract_response(struct getdns_dict *response, struct extracted_response *ex_response); 
void assert_noerror(struct extracted_response *ex_response);
void assert_nodata(struct extracted_response *ex_response);
void assert_address_in_answer(struct extracted_response *ex_response, int a, int aaaa);
void assert_nxdomain(struct extracted_response *ex_response);
void assert_soa_in_authority(struct extracted_response *ex_response);
void assert_ptr_in_answer(struct extracted_response *ex_response);

START_TEST (getdns_address_sync_1)
{
 /*
  *  context = NULL
  *  expect: GETDNS_RETURN_BAD_CONTEXT
  */
  STANDARD_TEST_DECLARATIONS;
  ASSERT_RC(getdns_address_sync(context, "google.com", NULL, &response), 
    GETDNS_RETURN_BAD_CONTEXT, "Return code from getdns_address_sync()");
}
END_TEST

START_TEST (getdns_address_sync_2)
{
 /*
  *  name = NULL
  *  expect: GETDNS_RETURN_GENERIC_ERROR
  */
  STANDARD_TEST_DECLARATIONS;
  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, NULL, NULL, &response), 
    GETDNS_RETURN_GENERIC_ERROR, "Return code from getdns_address_sync()");
}
END_TEST

START_TEST (getdns_address_sync_3)
{
 /*
  *  name = invalid domain (too many octets)
  *  expect:  GETDNS_RETURN_BAD_DOMAIN_NAME
  */
  STANDARD_TEST_DECLARATIONS;
  const char *name = "oh.my.gosh.and.for.petes.sake.are.you.fricking.crazy.man.because.this.spectacular.and.elaborately.thought.out.domain.name.of.very.significant.length.is.just.too.darn.long.because.you.know.the rfc.states.that.two.hundred.fifty.five.characters.is.the.max.com";
  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, name, NULL, &response), 
    GETDNS_RETURN_BAD_DOMAIN_NAME, "Return code from getdns_address_sync()");
}
END_TEST

START_TEST (getdns_address_sync_4)
{
 /*
  *  name = invalid domain (label too long)
  *  expect: GETDNS_RETURN_BAD_DOMAIN_NAME
  */
  STANDARD_TEST_DECLARATIONS;
  const char *name = "this.domain.hasalabelwhichexceedsthemaximumdnslabelsizeofsixtythreecharacters.com";
  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, name, NULL, &response), 
    GETDNS_RETURN_BAD_DOMAIN_NAME, "Return code from getdns_address_sync()");
}
END_TEST

START_TEST (getdns_address_sync_5)
{
 /*
  *  response = NULL
  *  expect:  GETDNS_RETURN_GENERIC_ERROR
  */
  STANDARD_TEST_DECLARATIONS;
  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, "google.com", NULL, NULL), 
    GETDNS_RETURN_GENERIC_ERROR, "Return code from getdns_address_sync()");
}
END_TEST

START_TEST (getdns_address_sync_6)
{
 /*
  *  name = "google.com"
  *  expect: NOERROR response:
  *    status = GETDNS_RETURN_GOOD
  *    rcode = 0
    todo:  create zonefile with exact count
  *    ancount = tbd (number of records in ANSWER section)
  */
  STANDARD_TEST_DECLARATIONS;

  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, "google.com", NULL, &response), 
    GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");
  EXTRACT_RESPONSE;
  assert_noerror(&ex_response);
}
END_TEST

START_TEST (getdns_address_sync_7)
{
 /*
  *  name = "localhost"
  *  expect: NOERROR response:
  *  expect:  GETDNS_RETURN_GOOD
  *    rcode = 0
    todo:  investigate that proper search order is set for resolution (is local being checked)
    todo:  create zonefile with exact count
  *    ancount = tbd (number of records in ANSWER section)
  */
  STANDARD_TEST_DECLARATIONS;

  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, "localhost", NULL, &response), 
    GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");
  EXTRACT_RESPONSE;
  assert_noerror(&ex_response);
}
END_TEST

START_TEST (getdns_address_sync_8)
{
 /*
  *  name = "google.joe"
  *    status = GETDNS_RETURN_GOOD for NXDOMAIN
  *    expect: NXDOMAIN response with SOA record
  *    rcode = 0
    todo:  investigate that proper search order is set for resolution (is local being checked)
    todo:  create host file with exact count 
  *    ancount >= 1 (number of records in ANSWER section)
  *      and one SOA record ("type": 6) in "answer" list
  */
  STANDARD_TEST_DECLARATIONS;

  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, "google.joe", NULL, &response), 
    GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");
  EXTRACT_RESPONSE;
  assert_nxdomain(&ex_response);
  assert_nodata(&ex_response);
  assert_soa_in_authority(&ex_response);
  //assert_address_in_answer(&ex_response, TRUE, FALSE);
}
END_TEST



START_TEST (getdns_address_sync_9)
{
 /*
  *  name = "hampster.com"  need to replace this with domain from unbound zone
  *  expect: NOERROR/NODATA response:
  *    status = GETDNS_RESPSTATUS_GOOD
  *    rcode = 0
  *    ancount = 0 (number of records in ANSWER section)
  */
  STANDARD_TEST_DECLARATIONS;

  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, "hampster.com", NULL, &response), 
    GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");
  EXTRACT_RESPONSE;
  assert_noerror(&ex_response);
}
END_TEST

START_TEST (getdns_address_sync_10)
{
 /*
  *    name = "google.com"  need to swap this out for max domain name length with max lable length`
  *    expect: NOERROR response with A records
  *    status = GETDNS_RESPSTATUS_GOOD
  *    rcode = 0
  *    ancount >= 11 (number of records in ANSWER section)
  */
  STANDARD_TEST_DECLARATIONS;

  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, "google.com", NULL, &response), 
    GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");
  EXTRACT_RESPONSE;
  printf("DICT:\n%s\n", getdns_pretty_print_dict(response));
  assert_noerror(&ex_response);
  assert_address_in_answer(&ex_response, TRUE, FALSE);
}
END_TEST

START_TEST (getdns_address_sync_11)
{
 /*
  *  name = "75.101.146.66"  need to change this to local unbound data
  *    status = GETDNS_RETURN_GOOD for NXDOMAIN
  *    expect: NXDOMAIN response with SOA record for NUMERICAL data 
  *    rcode = 0
  *    ancount >= 1 (number of records in ANSWER section)
  *      and one SOA record ("type": 6) in "answer" list
  */
  STANDARD_TEST_DECLARATIONS;

  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, "75.101.146.66", NULL, &response), 
    GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");
  EXTRACT_RESPONSE;
  printf("DICT:\n%s\n", getdns_pretty_print_dict(response));
  assert_nxdomain(&ex_response);
  assert_nodata(&ex_response);
  assert_soa_in_authority(&ex_response);
}
END_TEST

START_TEST (getdns_address_sync_12)
{
 /*
  *  name = "2607:f8b0:4006:802::1007"  need to change this to local unbound data
  *    status = GETDNS_RETURN_GOOD for NXDOMAIN
  *    expect: NXDOMAIN response with SOA record for NUMERICAL data 
  *    rcode = 0
  *    ancount >= 1 (number of records in ANSWER section)
  *      and one SOA record ("type": 6) in "answer" list
  */
  STANDARD_TEST_DECLARATIONS;

  CONTEXT_CREATE;
  ASSERT_RC(getdns_address_sync(context, "2607:f8b0:4006:802::1007", NULL, &response), 
    GETDNS_RETURN_GOOD, "Return code from getdns_address_sync()");
  EXTRACT_RESPONSE;
  printf("DICT:\n%s\n", getdns_pretty_print_dict(response));
  assert_nxdomain(&ex_response);
  assert_nodata(&ex_response);
  assert_soa_in_authority(&ex_response);
}
END_TEST

Suite *
getdns_address_sync_suite (void)
{
  Suite *s = suite_create ("getdns_address_sync()");

  /* Negative test caseis */
  TCase *tc_neg = tcase_create("Negative");
  tcase_add_test(tc_neg, getdns_address_sync_1);
  tcase_add_test(tc_neg, getdns_address_sync_2);
  tcase_add_test(tc_neg, getdns_address_sync_3);
  tcase_add_test(tc_neg, getdns_address_sync_4);
  tcase_add_test(tc_neg, getdns_address_sync_5);
  suite_add_tcase(s, tc_neg);
  /* Positive test cases */
  TCase *tc_pos = tcase_create("Positive");

  tcase_add_test(tc_pos, getdns_address_sync_6);
  tcase_add_test(tc_pos, getdns_address_sync_7);
  tcase_add_test(tc_pos, getdns_address_sync_8);
  tcase_add_test(tc_pos, getdns_address_sync_9);
  tcase_add_test(tc_pos, getdns_address_sync_10);
  tcase_add_test(tc_pos, getdns_address_sync_11);
  tcase_add_test(tc_pos, getdns_address_sync_12);
  suite_add_tcase(s, tc_pos);

  return s;
}

/*
 *  extract_response extracts all of the various information
 *  a test may want to look at from the response.
 */
void extract_response(struct getdns_dict *response, struct extracted_response *ex_response)
{
  size_t buflen = MAXLEN;
  char error_string[MAXLEN];

  ck_assert_msg(response != NULL, "Response should not be NULL");

  ASSERT_RC(getdns_dict_get_int(response, "answer_type", &ex_response->top_answer_type), 
    GETDNS_RETURN_GOOD, "Failed to extract \"top answer_type\"");

  ASSERT_RC(getdns_dict_get_bindata(response, "canonical_name", &ex_response->top_canonical_name), 
    GETDNS_RETURN_GOOD, "Failed to extract \"top canonical_name\"");

  ASSERT_RC(getdns_dict_get_list(response, "just_address_answers", &ex_response->just_address_answers), 
    GETDNS_RETURN_GOOD, "Failed to extract \"just_address_answers\"");
  ck_assert_msg(ex_response->just_address_answers != NULL, "just_address_answers should not be NULL");

  ASSERT_RC(getdns_dict_get_list(response, "replies_full", &ex_response->replies_full), 
    GETDNS_RETURN_GOOD, "Failed to extract \"replies_full\"");
  ck_assert_msg(ex_response->replies_full != NULL, "replies_full should not be NULL");

  ASSERT_RC(getdns_dict_get_list(response, "replies_tree", &ex_response->replies_tree), 
    GETDNS_RETURN_GOOD, "Failed to extract \"replies_tree\"");
  ck_assert_msg(ex_response->replies_tree != NULL, "replies_tree should not be NULL");

  ASSERT_RC(getdns_list_get_dict(ex_response->replies_tree, 0, &ex_response->replies_tree_sub_dict), 
    GETDNS_RETURN_GOOD, "Failed to extract \"replies_tree[0]\"");
  ck_assert_msg(ex_response->replies_tree_sub_dict != NULL, "replies_tree[0] dict should not be NULL");

  ASSERT_RC(getdns_dict_get_list(ex_response->replies_tree_sub_dict, "additional", &ex_response->additional),
    GETDNS_RETURN_GOOD, "Failed to extract \"additional\"");
  ck_assert_msg(ex_response->additional != NULL, "additional should not be NULL");

  ASSERT_RC(getdns_dict_get_list(ex_response->replies_tree_sub_dict, "answer", &ex_response->answer), 
    GETDNS_RETURN_GOOD, "Failed to extract \"answer\"");
  ck_assert_msg(ex_response->answer != NULL, "answer should not be NULL");

  ASSERT_RC(getdns_dict_get_int(ex_response->replies_tree_sub_dict, "answer_type", &ex_response->answer_type), 
    GETDNS_RETURN_GOOD, "Failed to extract \"answer_type\"");

  ASSERT_RC(getdns_dict_get_list(ex_response->replies_tree_sub_dict, "authority", &ex_response->authority), 
    GETDNS_RETURN_GOOD, "Failed to extract \"authority\"");
  ck_assert_msg(ex_response->authority != NULL, "authority should not be NULL");

  ASSERT_RC(getdns_dict_get_bindata(ex_response->replies_tree_sub_dict, "canonical_name", &ex_response->canonical_name), 
    GETDNS_RETURN_GOOD, "Failed to extract \"canonical_name\"");

  ASSERT_RC(getdns_dict_get_dict(ex_response->replies_tree_sub_dict, "header", &ex_response->header), 
    GETDNS_RETURN_GOOD, "Failed to extract \"header\"");
  ck_assert_msg(ex_response->header != NULL, "header should not be NULL");

  ASSERT_RC(getdns_dict_get_dict(ex_response->replies_tree_sub_dict, "question", &ex_response->question), 
    GETDNS_RETURN_GOOD, "Failed to extract \"question\"");
  ck_assert_msg(ex_response->question != NULL, "question should not be NULL");

  ASSERT_RC(getdns_dict_get_int(response, "status", &ex_response->status), 
    GETDNS_RETURN_GOOD, "Failed to extract \"status\"");
}

/*
 *  assert_noerror asserts that the rcode is 0
 */
void assert_noerror(struct extracted_response *ex_response)
{
  size_t buflen = MAXLEN;
  char error_string[MAXLEN];
  uint32_t rcode;

  ASSERT_RC(ex_response->status, GETDNS_RESPSTATUS_GOOD, "Unexpected value for \"status\"");
  ASSERT_RC(getdns_dict_get_int(ex_response->header, "rcode", &rcode), GETDNS_RETURN_GOOD, "Failed to extract \"rcode\"");
  ck_assert_msg(rcode == 0, "Expected rcode == 0, got %d", rcode);
}

/*
 *  assert_nodata asserts that ancount in the header and the
 *  of the answer section (list) are both zero.
 */ 
void assert_nodata(struct extracted_response *ex_response)
{
  size_t buflen = MAXLEN;
  char error_string[MAXLEN];
  uint32_t ancount;
  size_t length;

  ASSERT_RC(getdns_dict_get_int(ex_response->header, "ancount", &ancount), 
    GETDNS_RETURN_GOOD, "Failed to extract \"ancount\"");
  ck_assert_msg(ancount == 0, "Expected ancount == 0, got %d", ancount);

  ASSERT_RC(getdns_list_get_length(ex_response->answer, &length), 
    GETDNS_RETURN_GOOD, "Failed to extract \"answer\" length");
  ck_assert_msg(length == 0, "Expected \"answer\" length == 0, got %d", length);
}

/*
 *  assert_address_records_in_answer asserts that ancount in the header
 *  is >= 1, ancount is equal to the length of "answer", and that all of
 *  the records in the answer section are A and/or AAAA resource records
 *  based on the value of the a/aaaa arguments.
 */
void assert_address_in_answer(struct extracted_response *ex_response, int a, int aaaa)
{
  size_t buflen = MAXLEN;
  char error_string[MAXLEN];
  uint32_t ancount; 
  size_t length;
  struct getdns_dict *rr_dict;
  uint32_t type;
  uint32_t address_records = 0;

  ASSERT_RC(getdns_dict_get_int(ex_response->header, "ancount", &ancount),
    GETDNS_RETURN_GOOD, "Failed to extract \"ancount\"");
  ck_assert_msg(ancount >= 1, "Expected ancount >= 1, got %d", ancount);

  ASSERT_RC(getdns_list_get_length(ex_response->answer, &length),
    GETDNS_RETURN_GOOD, "Failed to extract \"answer\" length");
  ck_assert_msg(length == ancount, "Expected \"answer\" length == ancount: %d, got %d", ancount, length);

  for(size_t i = 0; i < length; i++)
  {
    ASSERT_RC(getdns_list_get_dict(ex_response->answer, i, &rr_dict), 
      GETDNS_RETURN_GOOD, "Failed to extract \"answer\" record");
    ASSERT_RC(getdns_dict_get_int(rr_dict, "type", &type), 
      GETDNS_RETURN_GOOD, "Failed to extract \"type\" from answer record");
    switch (type)
    {
      case GETDNS_RRTYPE_A:
        if(a && type == GETDNS_RRTYPE_A)
          address_records++;
      case GETDNS_RRTYPE_AAAA:
        if(aaaa && type == GETDNS_RRTYPE_AAAA)
          address_records++;
    }
  }
  ck_assert_msg(ancount == address_records, "ancount: %d address records mismatch: %d",
    ancount, address_records);
}

/*
 *  assert_nxdomain asserts that an NXDOMAIN response was
 *  was returned for the DNS query meaning:
 *  	rcode == 3
 */
void assert_nxdomain(struct extracted_response *ex_response)
{
  size_t buflen = MAXLEN;
  char error_string[MAXLEN];
  uint32_t rcode;

  ASSERT_RC(ex_response->status, GETDNS_RESPSTATUS_GOOD, "Unexpected value for \"status\"");
  ASSERT_RC(getdns_dict_get_int(ex_response->header, "rcode", &rcode), GETDNS_RETURN_GOOD, "Failed to extract \"rcode\"");
  ck_assert_msg(rcode == 3, "Expected rcode == 0, got %d", rcode);
}

/*
 *  assert_soa_in_authority asserts that a SOA record was
 *  returned in the authority sections.
 */
void assert_soa_in_authority(struct extracted_response *ex_response)
{
  size_t buflen = MAXLEN;
  char error_string[MAXLEN];
  uint32_t nscount;
  size_t length;
  struct getdns_dict *rr_dict;
  uint32_t type;
  uint32_t soa_records = 0;

  ASSERT_RC(getdns_dict_get_int(ex_response->header, "nscount", &nscount),
    GETDNS_RETURN_GOOD, "Failed to extract \"nscount\"");
  ck_assert_msg(nscount >= 1, "Expected nscount >= 1, got %d", nscount);

  ASSERT_RC(getdns_list_get_length(ex_response->authority, &length),
    GETDNS_RETURN_GOOD, "Failed to extract \"authority\" length");
  ck_assert_msg(length == nscount, "Expected \"authority\" length == nscount: %d, got %d", nscount, length);

  for(size_t i = 0; i < length; i++)
  {
    ASSERT_RC(getdns_list_get_dict(ex_response->authority, i, &rr_dict),
      GETDNS_RETURN_GOOD, "Failed to extract \"authority\" record");
    ASSERT_RC(getdns_dict_get_int(rr_dict, "type", &type),
      GETDNS_RETURN_GOOD, "Failed to extract \"type\" from authority record");
    if(type == GETDNS_RRTYPE_SOA)
      soa_records++;
  }

  ck_assert_msg(soa_records == 1, "Expected to find one SOA record in authority section, got %d", soa_records);
}

/*
 *  assert_ptr_in_answer asserts that a PTR record was
 *  returned in the answer sections.
 */
void assert_ptr_in_answer(struct extracted_response *ex_response)
{
  size_t buflen = MAXLEN;
  char error_string[MAXLEN];
  uint32_t ancount;
  size_t length;
  struct getdns_dict *rr_dict;
  uint32_t type;
  uint32_t ptr_records = 0;

  ASSERT_RC(getdns_dict_get_int(ex_response->header, "ancount", &ancount),
    GETDNS_RETURN_GOOD, "Failed to extract \"nscount\"");
  ck_assert_msg(ancount >= 1, "Expected ancount >= 1, got %d", ancount);

  ASSERT_RC(getdns_list_get_length(ex_response->answer, &length),
    GETDNS_RETURN_GOOD, "Failed to extract \"answer\" length");
  ck_assert_msg(length == ancount, "Expected \"answer\" length == ancount: %d, got %d", ancount, length);

  for(size_t i = 0; i < length; i++)
  {
    ASSERT_RC(getdns_list_get_dict(ex_response->answer, i, &rr_dict),
      GETDNS_RETURN_GOOD, "Failed to extract \"answer\" record");
    ASSERT_RC(getdns_dict_get_int(rr_dict, "type", &type),
      GETDNS_RETURN_GOOD, "Failed to extract \"type\" from answer record");
    if(type == GETDNS_RRTYPE_PTR)
      ptr_records++;
  }

  ck_assert_msg(ptr_records == 1, "Expected to find one PTR record in answer section, got %d", ptr_records);
}

int
main (void)
{
  int number_failed;
  Suite *s = getdns_address_sync_suite();
  SRunner *sr = srunner_create(s);
  srunner_set_log(sr, "getdns_address_sync_test.log");
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
