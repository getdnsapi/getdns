/**
 *
 * getdns list management functions, note that the internal storage is
 * accomplished via the libc binary search tree implementation so your
 * pointer foo needs to be keen to digest some of the internal semantics
 *
 * Interfaces originally taken from the getdns API description pseudo implementation.
 *
 */

/*
 * Copyright (c) 2013, Versign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <ldns/buffer.h>
#include "types-internal.h"
#include "util-internal.h"
#include "dict.h"

/*---------------------------------------- getdns_dict_find */
/**
 * private function used to locate a key in a dictionary
 * @param dict dicitonary to search
 * @param key key to search for
 * @param addifnotfnd if TRUE then an item will be added if the key is not found
 * @return pointer to dictionary item, caller must not free storage associated with item
 * @return NULL if additnotfnd == FALSE and key is not in dictionary
 */
struct getdns_dict_item *
getdns_dict_find(struct getdns_dict *dict, char *key, int addifnotfnd)
{
	struct getdns_dict_item *item;

	if (!dict || !key)
		return NULL;

	item = (struct getdns_dict_item *)
	       ldns_rbtree_search(&(dict->root), key);

	if (!item && addifnotfnd) {
		/* tsearch will add a node automatically for us */
		item = GETDNS_MALLOC(dict->mf, struct getdns_dict_item);
		item->node.key = getdns_strdup(&dict->mf, key);
		item->data.n = 0;
		ldns_rbtree_insert(&(dict->root), (ldns_rbnode_t *) item);
	}
	return item;
}				/* getdns_dict_find */

/*---------------------------------------- getdns_dict_get_names
*/
getdns_return_t
getdns_dict_get_names(struct getdns_dict * dict, struct getdns_list ** answer)
{
	struct getdns_dict_item *item;
	size_t index;
	struct getdns_bindata bindata;

	if (!dict || !answer)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	*answer = getdns_list_create_with_extended_memory_functions(
	    dict->mf.mf_arg, dict->mf.mf.ext.malloc,
	    dict->mf.mf.ext.realloc, dict->mf.mf.ext.free);
	if (!*answer)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	LDNS_RBTREE_FOR(item, struct getdns_dict_item *, &(dict->root)) {
		if (getdns_list_add_item(*answer, &index) != GETDNS_RETURN_GOOD)
			continue;
		bindata.size = strlen(item->node.key) + 1;
		bindata.data = (void *) item->node.key;
		getdns_list_set_bindata(*answer, index, &bindata);
	}
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_get_names */

/*---------------------------------------- getdns_dict_get_data_type */
getdns_return_t
getdns_dict_get_data_type(struct getdns_dict * dict, char *name,
    getdns_data_type * answer)
{
	struct getdns_dict_item *item;

	if (!dict || !name || !answer)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	item = getdns_dict_find(dict, name, 0);
	if (!item)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	*answer = item->dtype;
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_get_data_type */

/*---------------------------------------- getdns_dict_get_dict */
getdns_return_t
getdns_dict_get_dict(struct getdns_dict * dict, char *name,
    struct getdns_dict ** answer)
{
	struct getdns_dict_item *item;

	if (!dict || !name || !answer)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	item = getdns_dict_find(dict, name, 0);
	if (!item || item->dtype != t_dict)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	*answer = item->data.dict;
	return  GETDNS_RETURN_GOOD;
}				/* getdns_dict_get_dict */

/*---------------------------------------- getdns_dict_get_list */
getdns_return_t
getdns_dict_get_list(struct getdns_dict * dict, char *name,
    struct getdns_list ** answer)
{
	struct getdns_dict_item *item;

	if (!dict || !name || !answer)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	item = getdns_dict_find(dict, name, 0);
	if (!item || item->dtype != t_list)
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;

	*answer = item->data.list;
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_get_list */

/*---------------------------------------- getdns_dict_get_bindata */
getdns_return_t
getdns_dict_get_bindata(struct getdns_dict * dict, char *name,
    struct getdns_bindata ** answer)
{
	struct getdns_dict_item *item;

	if (!dict || !name || !answer)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	item = getdns_dict_find(dict, name, 0);
	if (!item || item->dtype != t_bindata)
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;

	*answer = item->data.bindata;
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_get_bindata */

/*---------------------------------------- getdns_dict_get_int */
getdns_return_t
getdns_dict_get_int(struct getdns_dict * dict, char *name, uint32_t * answer)
{
	struct getdns_dict_item *item;

	if (!dict || !name || !answer)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	item = getdns_dict_find(dict, name, 0);
	if (!item || item->dtype != t_int)
		return GETDNS_RETURN_WRONG_TYPE_REQUESTED;

	*answer = item->data.n;
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_get_int */

struct getdns_dict *
getdns_dict_create_with_extended_memory_functions(
    void *userarg,
    void *(*malloc)(void *userarg, size_t),
    void *(*realloc)(void *userarg, void *, size_t),
    void (*free)(void *userarg, void *))
{
	struct getdns_dict *dict;
	mf_union mf;

	if (!malloc || !realloc || !free)
		return NULL;

	mf.ext.malloc = malloc;
	dict = userarg == MF_PLAIN
	     ? (struct getdns_dict*)(*mf.pln.malloc)(
	           sizeof(struct getdns_dict))
	     : (struct getdns_dict*)(*mf.ext.malloc)(userarg,
	           sizeof(struct getdns_dict));
	if (!dict)
		return NULL;

	dict->mf.mf_arg         = userarg;
	dict->mf.mf.ext.malloc  = malloc;
	dict->mf.mf.ext.realloc = realloc;
	dict->mf.mf.ext.free    = free;

	ldns_rbtree_init(&(dict->root),
	    (int (*)(const void *, const void *)) strcmp);
	return dict;
}

struct getdns_dict *
getdns_dict_create_with_memory_functions(void *(*malloc)(size_t),
    void *(*realloc)(void *, size_t), void (*free)(void *))
{
	mf_union mf;
	mf.pln.malloc = malloc;
	mf.pln.realloc = realloc;
	mf.pln.free = free;
	return getdns_dict_create_with_extended_memory_functions(
	    MF_PLAIN, mf.ext.malloc, mf.ext.realloc, mf.ext.free);
}

/*-------------------------- getdns_dict_create_with_context */
struct getdns_dict *
getdns_dict_create_with_context(struct getdns_context *context)
{
	if (context)
		return getdns_dict_create_with_extended_memory_functions(
		    context->mf.mf_arg, context->mf.mf.ext.malloc,
		    context->mf.mf.ext.realloc, context->mf.mf.ext.free);
	else
		return getdns_dict_create_with_memory_functions(&malloc,
		    &realloc, &free);
}			/* getdns_dict_create_with_context */

/*---------------------------------------- getdns_dict_create */
struct getdns_dict *
getdns_dict_create()
{
	return getdns_dict_create_with_context(NULL);
}					/* getdns_dict_create */

/*---------------------------------------- getdns_dict_copy */
/**
 * private function used to make a copy of a dict structure,
 * the caller is responsible * for freeing storage allocated to returned value
 * @param srcdict the dictionary structure to copy
 * @param dstdict the copy destination
 * @return the address of the copy of the dictionary structure on success
 * @return NULL on error (out of memory, invalid srcdict)
 */
getdns_return_t
getdns_dict_copy(struct getdns_dict * srcdict, struct getdns_dict ** dstdict)
{
	struct getdns_dict_item *item;
	char *key;
	getdns_return_t retval;

	if (!dstdict)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	if (!srcdict) {
		*dstdict = NULL;
		return GETDNS_RETURN_GOOD;
	}
	*dstdict = getdns_dict_create_with_extended_memory_functions(
	    srcdict->mf.mf_arg,
	    srcdict->mf.mf.ext.malloc,
	    srcdict->mf.mf.ext.realloc,
	    srcdict->mf.mf.ext.free);
	if (!*dstdict)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	retval = GETDNS_RETURN_GOOD;
	LDNS_RBTREE_FOR(item, struct getdns_dict_item *, &(srcdict->root)) {
		key = (char *) item->node.key;
		switch (item->dtype) {
		case t_bindata:
			retval = getdns_dict_set_bindata(*dstdict, key,
			    item->data.bindata);
			break;

		case t_dict:
			retval = getdns_dict_set_dict(*dstdict, key,
			    item->data.dict);
			break;

		case t_int:
			retval = getdns_dict_set_int(*dstdict, key,
			    item->data.n);
			break;

		case t_list:
			retval = getdns_dict_set_list(*dstdict, key,
			    item->data.list);
			break;
		}
		if (retval != GETDNS_RETURN_GOOD) {
			getdns_dict_destroy(*dstdict);;
			*dstdict = NULL;
			return retval;
		}
	}
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_copy */

/*---------------------------------------- getdns_dict_item_free */
/**
 * private function used to release storage associated with a dictionary item
 * @param item all memory in this structure and its children will be freed
 * @return void
 */
void
getdns_dict_item_free(ldns_rbnode_t * node, void *arg)
{
	struct getdns_dict_item *item = (struct getdns_dict_item *) node;
	struct getdns_dict *dict = (struct getdns_dict *)arg;

	if (!item)
		return;

	switch (item->dtype) {
	case t_bindata:
		getdns_bindata_destroy(&dict->mf, item->data.bindata);
		break;
	case t_dict:
		getdns_dict_destroy(item->data.dict);
		break;
	case t_list:
		getdns_list_destroy(item->data.list);
		break;
	default:
		break;
	}
	if (item->node.key)
		GETDNS_FREE(dict->mf, (void *)item->node.key);
	GETDNS_FREE(dict->mf, item);
}				/* getdns_dict_item_free */

/*---------------------------------------- getdns_dict_destroy */
void
getdns_dict_destroy(struct getdns_dict *dict)
{
	if (!dict)
       		return;

	ldns_traverse_postorder(&(dict->root),
	    getdns_dict_item_free, dict);
	GETDNS_FREE(dict->mf, dict);
}				/* getdns_dict_destroy */

/*---------------------------------------- getdns_dict_set_dict */
getdns_return_t
getdns_dict_set_dict(struct getdns_dict * dict, char *name,
    struct getdns_dict * child_dict)
{
	struct getdns_dict_item *item;
	struct getdns_dict *newdict;
	getdns_return_t retval;

	if (!dict || !name || !child_dict)
		return GETDNS_RETURN_INVALID_PARAMETER;

	retval = getdns_dict_copy(child_dict, &newdict);
	if (retval != GETDNS_RETURN_GOOD)
		return retval;

	item = getdns_dict_find(dict, name, 1);
	if (!item) {
		getdns_dict_destroy(newdict);
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;
	}
	item->dtype = t_dict;
	item->data.dict = newdict;
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_set_dict */

/*---------------------------------------- getdns_dict_set_list */
getdns_return_t
getdns_dict_set_list(struct getdns_dict * dict, char *name,
    struct getdns_list * child_list)
{
	struct getdns_dict_item *item;
	struct getdns_list *newlist;
	getdns_return_t retval;

	if (!dict || !name)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	retval = getdns_list_copy(child_list, &newlist);
	if (retval != GETDNS_RETURN_GOOD)
		return retval;

	item = getdns_dict_find(dict, name, 1);
	if (!item) {
		getdns_list_destroy(newlist);
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;
	}
	item->dtype = t_list;
	item->data.list = newlist;
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_set_list */

/*---------------------------------------- getdns_dict_set_bindata */
getdns_return_t
getdns_dict_set_bindata(struct getdns_dict * dict, char *name,
    struct getdns_bindata * child_bindata)
{
	struct getdns_dict_item *item;
	struct getdns_bindata *newbindata;

	if (!dict || !name || !child_bindata)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	newbindata = getdns_bindata_copy(&dict->mf, child_bindata);
	if (!newbindata)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	item = getdns_dict_find(dict, name, 1);
	if (!item) {
		getdns_bindata_destroy(&dict->mf, newbindata);
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;
	}
	item->dtype = t_bindata;
	item->data.bindata = newbindata;
	return GETDNS_RETURN_GOOD;
}				/* getdns_dict_set_bindata */

/*---------------------------------------- getdns_dict_set_int */
getdns_return_t
getdns_dict_set_int(struct getdns_dict * dict, char *name,
    uint32_t child_uint32)
{
	struct getdns_dict_item *item;

	if (!dict || !name)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	item = getdns_dict_find(dict, name, 1);
	if (!item)
		return GETDNS_RETURN_NO_SUCH_DICT_NAME;

	item->dtype = t_int;
	item->data.n = child_uint32;
	return  GETDNS_RETURN_GOOD;
}				/* getdns_dict_set_int */

/*---------------------------------------- getdns_pp_dict */
/**
 * private function to help with indenting.
 * @param indent number of spaces to return
 * @return       a character string containing min(80, indent) spaces
 */
static const char *
getdns_indent(size_t indent)
{
	static const char *spaces = "                                        "
	    "                                        ";
	return spaces + 80 - (indent < 80 ? indent : 0);
}				/* getdns_indent */

/*---------------------------------------- getdns_pp_bindata */
/**
 * private function to pretty print bindata to a ldns_buffer
 * @param buf     buffer to write to
 * @param indent  number of spaces to append after newline
 * @param bindata the bindata to print
 * @return        on success the number of written characters
 *                if an output error is encountered, a negative value
 */
static int
getdns_pp_bindata(ldns_buffer * buf, size_t indent,
    struct getdns_bindata *bindata)
{
	size_t i, p = ldns_buffer_position(buf);
	uint8_t *dptr;

	if (ldns_buffer_printf(buf, " <bindata ") < 0)
		return -1;

	/* Walk through all printable characters */
	i = 0;
	if (bindata->size && bindata->data[bindata->size - 1] == 0)
		while (i < bindata->size - 1 && isprint(bindata->data[i]))
			i++;

	if (i >= bindata->size - 1) {	/* all chars were printable */
		if (ldns_buffer_printf(buf, "for \"%s\">", bindata->data) < 0)
			return -1;
	} else {
		if (ldns_buffer_printf(buf, "of 0x") < 0)
			return -1;
		for (dptr = bindata->data;
		    dptr < bindata->data + bindata->size; dptr++) {
			if (dptr - bindata->data >= 16) {
				if (ldns_buffer_printf(buf, "...") < 0)
					return -1;
				break;
			}
			if (ldns_buffer_printf(buf, "%.2x", *dptr) < 0)
				return -1;
		}
		if (ldns_buffer_printf(buf, ">") < 0)
			return -1;
	}
	return ldns_buffer_position(buf) - p;
}				/* getdns_pp_bindata */

static int
getdns_pp_dict(ldns_buffer * buf, size_t indent, struct getdns_dict *dict);

/*---------------------------------------- getdns_pp_list */
/**
 * private function to pretty print list to a ldns_buffer
 * @param buf    buffer to write to
 * @param indent number of spaces to append after newline
 * @param list   the to list print
 * @return       on success the number of written characters
 *               if an output error is encountered, a negative value
 */
static int
getdns_pp_list(ldns_buffer * buf, size_t indent, struct getdns_list *list)
{
	size_t i, length, p = ldns_buffer_position(buf);
	getdns_data_type dtype;
	struct getdns_dict *dict_item;
	struct getdns_list *list_item;
	struct getdns_bindata *bindata_item;
	uint32_t int_item;

	if (list == NULL)
		return 0;

	if (ldns_buffer_printf(buf, "[") < 0)
		return -1;

	if (getdns_list_get_length(list, &length) != GETDNS_RETURN_GOOD)
		return -1;

	indent += 2;
	for (i = 0; i < length; i++) {
		if (ldns_buffer_printf(buf, "%s\n%s", (i ? "," : ""),
			getdns_indent(indent)) < 0)
			return -1;

		if (getdns_list_get_data_type(list, i,
			&dtype) != GETDNS_RETURN_GOOD)
			return -1;

		switch (dtype) {
		case t_int:
			if (getdns_list_get_int(list, i, &int_item) !=
			    GETDNS_RETURN_GOOD)
				if (ldns_buffer_printf(buf, " %d",
					(int) int_item) < 0)
					return -1;
			break;

		case t_bindata:
			if (getdns_list_get_bindata(list, i, &bindata_item) !=
			    GETDNS_RETURN_GOOD)
				return -1;
			if (getdns_pp_bindata(buf, indent, bindata_item) < 0)
				return -1;
			break;

		case t_list:
			if (getdns_list_get_list(list, i, &list_item) !=
			    GETDNS_RETURN_GOOD)
				return -1;
			if (getdns_pp_list(buf, indent, list_item) < 0)
				return -1;
			break;

		case t_dict:
			if (getdns_list_get_dict(list, i, &dict_item) !=
			    GETDNS_RETURN_GOOD)
				return -1;
			if (getdns_pp_dict(buf, indent, dict_item) < 0)
				return -1;
			break;

		default:
			if (ldns_buffer_printf(buf, " <unknown>") < 0)
				return -1;
		}
	}
	indent -= 2;
	if (ldns_buffer_printf(buf, i ? "\n%s]" : "]",
		getdns_indent(indent)) < 0)
		return -1;

	return ldns_buffer_position(buf) - p;
}				/* getdns_pp_list */

/*---------------------------------------- getdns_pp_dict */
/**
 * private function to pretty print dict to a ldns_buffer
 * @param buf    buffer to write to
 * @param indent number of spaces to append after newline
 * @param dict   the dict to print
 * @return       on success the number of written characters
 *               if an output error is encountered, a negative value
 */
static int
getdns_pp_dict(ldns_buffer * buf, size_t indent, struct getdns_dict *dict)
{
	size_t i, length, p = ldns_buffer_position(buf);
	struct getdns_dict_item *item;

	if (dict == NULL)
		return 0;

	if (ldns_buffer_printf(buf, "{") < 0)
		return -1;

	i = 0;
	indent += 2;
	LDNS_RBTREE_FOR(item, struct getdns_dict_item *, &(dict->root)) {
		if (ldns_buffer_printf(buf, "%s\n%s\"%s\":", (i ? "," : "")
			, getdns_indent(indent)
			, item->node.key) < 0)
			return -1;

		switch (item->dtype) {
		case t_int:
			if (ldns_buffer_printf(buf, " %d", item->data.n) < 0)
				return -1;
			break;

		case t_bindata:
			if (getdns_pp_bindata(buf, indent,
				item->data.bindata) < 0)
				return -1;
			break;

		case t_list:	/* Don't put empty lists on a new line */

			if (getdns_list_get_length(item->data.list,
				&length) != GETDNS_RETURN_GOOD)
				return -1;
			if (length == 0) {
				if (ldns_buffer_printf(buf, " []") < 0)
					return -1;
				break;
			}
			if (ldns_buffer_printf(buf, "\n%s",
				getdns_indent(indent)) < 0)
				return -1;
			if (getdns_pp_list(buf, indent, item->data.list) < 0)
				return -1;
			break;

		case t_dict:
			if (ldns_buffer_printf(buf, "\n%s",
				getdns_indent(indent)) < 0)
				return -1;
			if (getdns_pp_dict(buf, indent, item->data.dict) < 0)
				return -1;
			break;

		default:
			if (ldns_buffer_printf(buf, " <unknown>") < 0)
				return -1;
		}
		i++;
	}
	indent -= 2;
	if (ldns_buffer_printf(buf, i ? "\n%s}" : "}",
		getdns_indent(indent)) < 0)
		return -1;

	return ldns_buffer_position(buf) - p;
}				/* getdns_pp_dict */

/*---------------------------------------- getdns_pretty_print_dict */
/**
 * Return a character string containing a "human readable" representation
 * of dict.
 * @param dict   the dict to pretty print
 * @return       the "human readable" representation of dict
 *               or NULL on error
 */
char *
getdns_pretty_print_dict(struct getdns_dict *dict)
{
	ldns_buffer *buf;
	char *ret;

	if (!dict)
		return NULL;

	buf = ldns_buffer_new(100);
	if (!buf)
		return NULL;

	if (getdns_pp_dict(buf, 0, dict) < 0) {
		ldns_buffer_free(buf);
		return NULL;
	}
	ret = (char *) ldns_buffer_export(buf);
	ldns_buffer_free(buf);
	return ret;
}				/* getdns_pretty_print_dict */

getdns_return_t
getdns_dict_remove_name(struct getdns_dict *this_dict, char *name)
{
	return GETDNS_RETURN_GENERIC_ERROR;
}

/* dict.c */
