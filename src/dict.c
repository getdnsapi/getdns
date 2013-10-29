/**
 *
 * getdns list management functions, note that the internal storage is 
 * accomplished via the libc binary search tree implementation so your
 * pointer foo needs to be keen to digest some of the internal semantics
 * 
 * Interfaces originally taken from the getdns API description pseudo implementation.
 *
 */
/* The MIT License (MIT)
 * Copyright (c) 2013 Verisign, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include "dict.h"

/*---------------------------------------- getdns_dict_cmp */
int
getdns_dict_cmp(const void *item1, const void *item2)
{ 
    return strcmp((const char *)item1, (const char *)item2);
} /* getdns_dict_comp */

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
getdns_dict_find(struct getdns_dict *dict, char *key, bool addifnotfnd)
{ 
    struct getdns_dict_item *item = NULL;

    if(dict != NULL && key != NULL)
    {
        item = (struct getdns_dict_item *)ldns_rbtree_search(&(dict->root), key);
        if(addifnotfnd == true && item == NULL)
        {
            /* tsearch will add a node automatically for us */
            item = (struct getdns_dict_item *) malloc(sizeof(struct getdns_dict_item));
            item->key      = strdup(key);
            item->node.key = item->key;
            item->dtype    = t_invalid;
            item->data.n   = 0;
            ldns_rbtree_insert(&(dict->root), (ldns_rbnode_t *)item);
        }
    }
    return item;
} /* getdns_dict_find */

/*---------------------------------------- getdns_dict_get_names
*/
getdns_return_t
getdns_dict_get_names(struct getdns_dict *dict, struct getdns_list **answer)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;
    struct getdns_dict_item *item;
    size_t index;

    if(dict != NULL && answer != NULL)
    {
        *answer = getdns_list_create();

        LDNS_RBTREE_FOR(item, struct getdns_dict_item *, &(dict->root))
        {
            if(getdns_list_add_item(*answer, &index) == GETDNS_RETURN_GOOD)
            {
                struct getdns_bindata bindata;
                bindata.size =  strlen(item->key);
                bindata.data = (void *)item->key;
                getdns_list_set_bindata(*answer, index, &bindata);
            }
        }
        retval = GETDNS_RETURN_GOOD;
    }
    return retval;
} /* getdns_dict_get_names */

/*---------------------------------------- getdns_dict_get_data_type */
getdns_return_t
getdns_dict_get_data_type(struct getdns_dict *dict, char *name, getdns_data_type *answer)
{ 
    struct getdns_dict_item *item;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL && answer != NULL)
    {
        item = getdns_dict_find(dict, name, false);
        if(item != NULL)
        {
            *answer = item->dtype;
            retval = GETDNS_RETURN_GOOD;
        }
    }

    return retval;
} /* getdns_dict_get_data_type */

/*---------------------------------------- getdns_dict_get_dict */
getdns_return_t
getdns_dict_get_dict(struct getdns_dict *dict, char *name, struct getdns_dict **answer)
{ 
    struct getdns_dict_item *item;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL && answer != NULL)
    {
        item = getdns_dict_find(dict, name, false);
        if(item != NULL)
        {
            if(item->dtype != t_dict)
                retval = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
            else
            {
                *answer = item->data.dict;
                retval = GETDNS_RETURN_GOOD;
            }
        }
    }

    return retval;
} /* getdns_dict_get_dict */

/*---------------------------------------- getdns_dict_get_list */
getdns_return_t
getdns_dict_get_list(struct getdns_dict *dict, char *name, struct getdns_list **answer)
{ 
    struct getdns_dict_item *item;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL && answer != NULL)
    {
        item = getdns_dict_find(dict, name, false);
        if(item != NULL)
        {
            if(item->dtype != t_list)
                retval = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
            else
            {
                *answer = item->data.list;
                retval = GETDNS_RETURN_GOOD;
            }
        }
    }

    return retval;
} /* getdns_dict_get_list */

/*---------------------------------------- getdns_dict_get_bindata */
getdns_return_t
getdns_dict_get_bindata(struct getdns_dict *dict, char *name, struct getdns_bindata **answer)
{ 
    struct getdns_dict_item *item;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL && answer != NULL)
    {
        item = getdns_dict_find(dict, name, false);
        if(item != NULL)
        {
            if(item->dtype != t_bindata)
                retval = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
            else
            {
                *answer = item->data.bindata;
                retval = GETDNS_RETURN_GOOD;
            }
        }
    }

    return retval;
} /* getdns_dict_get_bindata */

/*---------------------------------------- getdns_dict_get_int */
getdns_return_t
getdns_dict_get_int(struct getdns_dict *dict, char *name, uint32_t *answer)
{ 
    struct getdns_dict_item *item;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL && answer != NULL)
    {
        item = getdns_dict_find(dict, name, false);
        if(item != NULL)
        {
            if(item->dtype != t_int)
                retval = GETDNS_RETURN_WRONG_TYPE_REQUESTED;
            else
            {
                *answer = item->data.n;
                retval = GETDNS_RETURN_GOOD;
            }
        }
    }

    return retval;
} /* getdns_dict_get_int */

/*---------------------------------------- getdns_dict_create */
struct getdns_dict *
getdns_dict_create()
{
    struct getdns_dict *dict;

    dict = (struct getdns_dict *) malloc(sizeof(struct getdns_dict));
    //ldns_rbtree_init(&(dict->root), getdns_dict_cmp);
    ldns_rbtree_init(&(dict->root), (int (*)(const void *, const void *))strcmp);
    return dict;
} /* getdns_dict_create */

/*---------------------------------------- getdns_dict_copy */
/**
 * private function used to make a copy of a dict structure, the caller is responsible
 * for freeing storage allocated to returned value
 * NOTE: not thread safe - this needs to be fixed to be thread safe
 * @param srcdict the dictionary structure to copy
 * @param dstdict the copy destination
 * @return the address of the copy of the dictionary structure on success
 * @return NULL on error (out of memory, invalid srcdict)
 */
getdns_return_t
getdns_dict_copy(struct getdns_dict *srcdict, struct getdns_dict **dstdict)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;
    struct getdns_dict_item *item;

    if(srcdict != NULL && dstdict != NULL)
    {
        *dstdict = getdns_dict_create();

        LDNS_RBTREE_FOR(item, struct getdns_dict_item *, &(srcdict->root))
        {
            switch(item->dtype)
            {
                case t_bindata:
                    getdns_dict_set_bindata(*dstdict, item->key, item->data.bindata);
                    break;

                case t_dict:
                    getdns_dict_set_dict(*dstdict, item->key, item->data.dict);
                    break;

                case t_int:
                    getdns_dict_set_int(*dstdict, item->key, item->data.n);
                    break;

                case t_list:
                    getdns_dict_set_list(*dstdict, item->key, item->data.list);
                    break;

                case t_invalid:
                default:
                    // TODO: this is a fault of some kind, for now ignore it
                    break;
            }
        }
        retval = GETDNS_RETURN_GOOD;
    }

    return retval;
} /* getdns_dict_copy */

/*---------------------------------------- getdns_dict_item_free */
/**
 * private function used to release storage associated with a dictionary item
 * @param item all memory in this structure and its children will be freed
 * @return void
 */
void
getdns_dict_item_free(ldns_rbnode_t *node, void *arg)
{
    (void) arg;
    struct getdns_dict_item *item = (struct getdns_dict_item *)node;
    if(item != NULL)
    {
        if(item->dtype == t_bindata)
        {
            if(item->data.bindata->size > 0)
                free(item->data.bindata->data);
            free(item->data.bindata);
        }
        else if(item->dtype == t_dict)
        {
            getdns_dict_destroy(item->data.dict);
        }
        else if(item->dtype == t_list)
        {
            getdns_list_destroy(item->data.list);
        }

        if(item->key != NULL)
            free(item->key);
        free(item);
    }
} /* getdns_dict_item_free */

/*---------------------------------------- getdns_dict_destroy */
void
getdns_dict_destroy(struct getdns_dict *dict)
{
    if(dict != NULL)
    {
        ldns_traverse_postorder(&(dict->root), getdns_dict_item_free, NULL);
        free(dict);
    }

    return;
} /* getdns_dict_destroy */

/*---------------------------------------- getdns_dict_set_dict */
getdns_return_t
getdns_dict_set_dict(struct getdns_dict *dict, char *name, struct getdns_dict *child_dict)
{ 
    struct getdns_dict_item *item;
    struct getdns_dict      *newdict;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL)
    {
        item = getdns_dict_find(dict, name, true);
        if(item != NULL)
        {
            retval = getdns_dict_copy(child_dict, &newdict);
            if(retval == GETDNS_RETURN_GOOD)
            {
                item->dtype     = t_dict;
                item->data.dict = newdict;
            }
            else
                item->dtype = t_invalid;
        }
    }

    return retval;
} /* getdns_dict_set_dict */

/*---------------------------------------- getdns_dict_set_list */
getdns_return_t
getdns_dict_set_list(struct getdns_dict *dict, char *name, struct getdns_list *child_list)
{ 
    struct getdns_dict_item *item;
    struct getdns_list      *newlist;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL)
    {
        item = getdns_dict_find(dict, name, true);
        if(item != NULL)
        {
            retval = getdns_list_copy(child_list, &newlist);
            if(retval == GETDNS_RETURN_GOOD)
            {
                item->dtype     = t_list;
                item->data.list = newlist;
            }
            else
                item->dtype = t_invalid;
        }
    }

    return retval;
} /* getdns_dict_set_list */

/*---------------------------------------- getdns_dict_set_bindata */
getdns_return_t
getdns_dict_set_bindata(struct getdns_dict *dict, char *name, struct getdns_bindata *child_bindata)
{ 
    struct getdns_dict_item *item;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL && child_bindata != NULL)
    {
        item = getdns_dict_find(dict, name, true);
        if(item != NULL)
        {
            item->dtype  = t_bindata;
            item->data.bindata = (struct getdns_bindata *) malloc(sizeof(struct getdns_bindata));
            if(item->data.bindata != NULL)
            {
                item->data.bindata->data = (void *) malloc(child_bindata->size);
                if(item->data.bindata->data != NULL)
                {
                    item->data.bindata->size =  child_bindata->size;
                    memcpy(item->data.bindata->data, child_bindata->data, child_bindata->size);
                    retval = GETDNS_RETURN_GOOD;
                }
            }
        }
    }

    return retval;
} /* getdns_dict_set_bindata */

/*---------------------------------------- getdns_dict_set_int */
getdns_return_t
getdns_dict_set_int(struct getdns_dict *dict, char *name, uint32_t child_uint32)
{ 
    struct getdns_dict_item *item;
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && name != NULL)
    {
        item = getdns_dict_find(dict, name, true);
        if(item != NULL)
        {
            item->dtype  = t_int;
            item->data.n = child_uint32;
            retval = GETDNS_RETURN_GOOD;
        }
    }

    return retval;
} /* getdns_dict_set_int */

/*---------------------------------------- getdns_pretty_print_dict */
char *
getdns_pretty_print_dict(struct getdns_dict *dict)
{
    struct getdns_dict_item *item;
    char buf[8192];
    size_t i;
    char* tmp;

    buf[0] = 0;

    if(dict != NULL)
    {
        i = 0;
        strcat(buf, "{");
        LDNS_RBTREE_FOR(item, struct getdns_dict_item *, &(dict->root))
        {
            if (i)
                strcat(buf, ", \"");
            else
                strcat(buf, " \"");
            strcat(buf, item->node.key);
            strcat(buf, "\": ");
            switch(item->dtype)
            {
                case t_bindata:
                    sprintf(buf + strlen(buf), "<bindata %d>", (int)item->data.bindata->size);
                    break;

                case t_dict:
                    tmp = getdns_pretty_print_dict(item->data.dict);
                    strcat(buf, tmp);
                    free(tmp);
                    break;

                case t_int:
                    sprintf(buf + strlen(buf), "%d", item->data.n);
                    break;

                case t_list:
                    strcat(buf, "[<not implemented>]");
                    break;

                case t_invalid:
                default:
                    strcat(buf, "<invalid>");
                    break;
            }
            i++;
        }
        if(i)
            strcat(buf, " ");
        strcat(buf, "}");
    }

    return strdup(buf);
} /* getdns_pretty_print_dict */

/* getdns_dict.c */
