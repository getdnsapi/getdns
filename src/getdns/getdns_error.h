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

struct getdns_struct_lookup_table
{				/* may or may not want to move this into */
	int id;			/* getdns.h if it's more generally useful */
	const char *name;
};

typedef struct getdns_struct_lookup_table getdns_lookup_table;

/**
 * \defgroup error_table error number to string mapping
 * @{
 */

extern getdns_lookup_table getdns_error_str[];

typedef enum getdns_enum_status getdns_status;
const char *getdns_get_errorstr_by_id(uint16_t err);

/** @}
 */

#endif /* GETDNS_ERROR_H */
