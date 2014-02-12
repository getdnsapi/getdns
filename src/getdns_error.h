/**
 * \file
 * @brief defines and data structure for getdns_error_str_by_id()
 *
 * This source was taken from the original pseudo-implementation by
 * Paul Hoffman.
 */

#ifndef GETDNS_ERROR_H
#define GETDNS_ERROR_H

#include <getdns/getdns.h>

const char *getdns_get_errorstr_by_id(uint16_t err);

/** @}
 */

#endif /* GETDNS_ERROR_H */
