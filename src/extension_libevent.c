
#include "config.h"
#include "context.h"
#ifdef HAVE_EVENT2_EVENT_H
#  include <event2/event.h>
#else
#  include <event.h>
#  define evutil_socket_t int
#  define event_free free
#  define evtimer_new(b, cb, arg) event_new((b), -1, 0, (cb), (arg))
#endif
#define RETURN_IF_NULL(ptr, code) if(ptr == NULL) return code;

#ifndef HAVE_EVENT2_EVENT_H
static struct event *
event_new(struct event_base *b, evutil_socket_t fd, short ev, void* cb, void *arg)
{
    struct event* e = (struct event*)calloc(1, sizeof(struct event));
    if(!e) return NULL;
    event_set(e, fd, ev, cb, arg);
    event_base_set(b, e);
    return e;
}
#endif /* no event2 */

void getdns_libevent_cb(evutil_socket_t fd, short what, void *userarg) {
    struct getdns_context* context = (struct getdns_context*) userarg;
    getdns_context_process_async(context);
}

/*
 * getdns_extension_set_libevent_base
 *
 */
getdns_return_t
getdns_extension_set_libevent_base(struct getdns_context *context,
    struct event_base * this_event_base)
{
    RETURN_IF_NULL(context, GETDNS_RETURN_BAD_CONTEXT);
    RETURN_IF_NULL(this_event_base, GETDNS_RETURN_INVALID_PARAMETER);
    /* TODO: cleanup current extension base */
    int fd = getdns_context_fd(context);
    struct event *getdns_event = event_new(this_event_base, fd, EV_READ | EV_PERSIST, getdns_libevent_cb, context);
    event_add(getdns_event, NULL);

    return GETDNS_RETURN_GOOD;
}               /* getdns_extension_set_libevent_base */
