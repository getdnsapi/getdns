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
     #define CONTEXT_CREATE					\
       ASSERT_RC(getdns_context_create(&context, TRUE),		\
         GETDNS_RETURN_GOOD, 					\
         "Return code from getdns_context_create()");

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
      *  The DICT_CREATE macro simply creates a 
      *  dict and verifies the returned pointer
      *  is not NULL.
      */
    #define DICT_CREATE(dict)		\
      dict = getdns_dict_create();	\
      ck_assert_msg(dict != NULL, 	\
        "NULL pointer returned by getdns_dict_create()");
     
     /*			
      *  The process_response macro declares the
      *  variables needed to house the response and
      *  calls the function that extracts it.
      */
     #define EXTRACT_RESPONSE			\
       struct extracted_response ex_response;	\
       extract_response(response, &ex_response);
      
     void extract_response(struct getdns_dict *response, struct extracted_response *ex_response); 
     void assert_noerror(struct extracted_response *ex_response);
     void assert_nodata(struct extracted_response *ex_response);
     void assert_address_in_answer(struct extracted_response *ex_response, int a, int aaaa);
     void assert_nxdomain(struct extracted_response *ex_response);
     void assert_soa_in_authority(struct extracted_response *ex_response);
     void assert_ptr_in_answer(struct extracted_response *ex_response);
     void negative_callbackfn(
       struct getdns_context *context, 
       uint16_t callback_type, 
       struct getdns_dict *response,
       void *userarg,
       getdns_transaction_t transaction_id
     );
     void positive_callbackfn(
       struct getdns_context *context, 
       uint16_t callback_type,
       struct getdns_dict *response, 
       void *userarg,
       getdns_transaction_t transaction_id
     );

#endif
