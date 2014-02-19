#include <event2/event.h>
#include <getdns_core_only.h>

/* For libevent, which we are using for these examples */
getdns_return_t
getdns_extension_set_libevent_base(
  getdns_context     *context,
  struct event_base  *this_event_base
);
