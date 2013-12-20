#ifndef _check_getdns_common_h_
#define _check_getdns_common_h_

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
      *  The ASSERT_RC macro is used to assert
      *  whether the return code from the last
      *  getdns API call is what was expected.
      */
     #define ASSERT_RC(rc, expected_rc, prefix)			\
     {                                          		\
       size_t buflen = MAXLEN;					\
       char error_string[MAXLEN];                		\
       getdns_strerror(rc, error_string, buflen);		\
       ck_assert_msg(rc == expected_rc,				\
         "%s: expecting %s: %d, but received: %d: %s",		\
         prefix, #expected_rc, expected_rc, rc, error_string);	\
     }
     
     /*
      *  The CONTEXT_CREATE macro is used to	
      *  create a context and assert the proper
      *  return code is returned.		
      */				
     #define CONTEXT_CREATE(set_from_os)			\
       ASSERT_RC(getdns_context_create(&context, set_from_os),	\
         GETDNS_RETURN_GOOD, 					\
         "Return code from getdns_context_create()");

     /*
      *  The CONTEXT_FREE macro is used to
      *  destroy the current context.
      */
     #define CONTEXT_DESTROY getdns_context_destroy(context);

     /*
      *  The EVENT_BASE_CREATE macro is used to 				
      *  create an event base and put it in the			
      *  context.						
      */						
     #define EVENT_BASE_CREATE							\
       event_base = event_base_new();						\
       ck_assert_msg(event_base != NULL, "Event base creation failed");		\
       ASSERT_RC(getdns_extension_set_libevent_base(context, event_base),	\
         GETDNS_RETURN_GOOD,							\
         "Return code from getdns_extension_set_libevent_base()");
     
     /*
      *   The RUN_EVENT_LOOP macro calls the event loop.
      */
     #define RUN_EVENT_LOOP event_base_dispatch(event_base);

     /*
      *  The LIST_CREATE macro simply creates a 
      *  list and verifies the returned pointer
      *  is not NULL.
      */
    #define LIST_CREATE(list)		\
      list = getdns_list_create();	\
      ck_assert_msg(list != NULL, 	\
        "NULL pointer returned by getdns_list_create()");

     /*
      *  The LIST_DESTROY macro destroys a list.
      */
     #define LIST_DESTROY(list) getdns_list_destroy(list);

     /*
      *  The DICT_CREATE macro simply creates a 
      *  dict and verifies the returned pointer
      *  is not NULL.
      */
    #define DICT_CREATE(dict)		\
      dict = getdns_dict_create();	\
      ck_assert_msg(dict != NULL, 	\
        "NULL pointer returned by getdns_dict_create()");

     /*
      *  The DICT_DESTROY macro destroys a dict.
      */
     #define DICT_DESTROY(dict) getdns_dict_destroy(dict);
     
     /*			
      *  The process_response macro declares the
      *  variables needed to house the response and
      *  calls the function that extracts it.
      */
     #define EXTRACT_RESPONSE			\
       struct extracted_response ex_response;	\
       extract_response(response, &ex_response);

     //
     //  FUNCTION DECLARATIONS 
     // 

     /*
      *    extract_response extracts all of the various information
      *    a test may want to look at from the response.
      */
     void extract_response(struct getdns_dict *response, struct extracted_response *ex_response); 

     /*
      *    assert_noerror asserts that the rcode is 0.
      */
     void assert_noerror(struct extracted_response *ex_response);

    /*
     *     assert_nodata asserts that ancount in the header and the
     *     of the answer section (list) are both zero.
     */
     void assert_nodata(struct extracted_response *ex_response);

     /*
      *    assert_address_records_in_answer asserts that ancount in 
      *    the header *    is >= 1, ancount is equal to the length 
      *    of "answer", and that all of *    the records in the 
      *    answer section are A and/or AAAA resource records based 
      *    on the value of the a/aaaa arguments.
      */
     void assert_address_in_answer(struct extracted_response *ex_response, int a, int aaaa);

     /*
      *    assert_nxdomain asserts that an NXDOMAIN response was
      *    was returned for the DNS query meaning rcode == 3.
      */
     void assert_nxdomain(struct extracted_response *ex_response);

     /*
      *    assert_soa_in_authority asserts that a SOA record was
      *    returned in the authority sections.
      */
     void assert_soa_in_authority(struct extracted_response *ex_response);

     /*
      *    assert_ptr_in_answer asserts that a PTR record was
      *    returned in the answer sections.
      */
     void assert_ptr_in_answer(struct extracted_response *ex_response);

     /*
      *    negative_callbackfn is the callback function given
      *    to negative asynchronous query tests when no response
      *    is expected.
      */
     void negative_callbackfn(
       struct getdns_context *context, 
       uint16_t callback_type, 
       struct getdns_dict *response,
       void *userarg,
       getdns_transaction_t transaction_id
     );

     /*
      *    positive_callbackfn is the callback function given
      *    to positive asynchronous query tests and will validate
      *    the response that is returned.
      */
     void positive_callbackfn(
       struct getdns_context *context, 
       uint16_t callback_type,
       struct getdns_dict *response, 
       void *userarg,
       getdns_transaction_t transaction_id
     );

#endif
