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
#include <search.h>
#include <string.h>
#include <getdns/getdns.h>

/* TODO: change this to make the walk safe for reentrant/multi-thread calls */
struct getdns_list *walkresultlist;
struct getdns_dict *walkresultdict;
char *walkresultchar;
int  walkresultcharlen;

/*---------------------------------------- getdns_dict_cmp */
/**
 * private function used by the t*() functions for managing binary trees
 * behaves similar to strcmp() 
 * @param itemp1 pointer to pointer to getdns_dict_item to compare
 * @param itemp2 pointer to pointer to getdns_dict_item to compare
 * @return results of lexicographic comparison between item1->key and item2->key
 */
int
getdns_dict_cmp(const void *item1, const void *item2)
{ 
    int retval = 0;

    if(item1 == NULL)
    {
        if(item2 == NULL)
            retval = 0;
        else
            retval = -1;
    }
    else if(item2 == NULL)
        retval = 1;
    else
    {
        retval = strcmp(((struct getdns_dict_item *) item1)->key
         , ((struct getdns_dict_item *) item2)->key);
    }

    return retval;
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
    struct getdns_dict_item keyitem;
    struct getdns_dict_item **item;
    struct getdns_dict_item *newitem;
    struct getdns_dict_item *ret = NULL;

    if(dict != NULL && key != NULL)
    {
        /* we try to find it first, if we do then clear the existing data */
        keyitem.key    = key;
        keyitem.dtype  = t_invalid;
        keyitem.data.n = 0;
        item = tfind(&keyitem, &(dict->rootp), getdns_dict_cmp);
        if(addifnotfnd == true && (item == NULL || *item == NULL))
        {
            /* tsearch will add a node automatically for us */
            newitem = (struct getdns_dict_item *) malloc(sizeof(struct getdns_dict_item));
            newitem->key    = strdup(key);
            newitem->dtype  = t_invalid;
            newitem->data.n = 0;
            item = tsearch(newitem, &(dict->rootp), getdns_dict_cmp);
        }
        if(item != NULL)
            ret = *item;
    }

    return ret;
} /* getdns_dict_find */

/*---------------------------------------- getdns_dict_visit */
/**
 * private function called by the tree walk function invoked by getdns_dict_get_names
 * it is called as each node is visited.  twalk() calls 3x for each node and passes order
 * to tell us whether it is a pre/in/post order
 */
void
getdns_dict_visit(const void *node, VISIT order, int level)
{
    struct getdns_dict_item *item;
    size_t index;

    item = *(struct getdns_dict_item **) node;
    /* postorder is mis-named - it results in in-order traversal */
    if(order == postorder || order == leaf)
    {
        if(getdns_list_add_item(walkresultlist, &index) == GETDNS_RETURN_GOOD)
        {
            switch(item->dtype)
            {
                case t_bindata:
                    getdns_list_set_bindata(walkresultlist, index, item->data.bindata);
                    break;

                case t_dict:
                    getdns_list_set_dict(walkresultlist, index, item->data.dict);
                    break;

                case t_int:
                    getdns_list_set_int(walkresultlist, index, item->data.n);
                    break;

                case t_list:
                    getdns_list_set_list(walkresultlist, index, item->data.list);
                    break;

                case t_invalid:
                default:
                    // TODO: this is a fault of some kind, for now ignore it
                    break;
            }
        }
    }

    return;
} /* getdns_dict_visit */

/*---------------------------------------- getdns_dict_get_names
 TODO: this needs to be made thread safe by creating a thread specific list
 the binary search tree implementation in the 
*/
getdns_return_t
getdns_dict_get_names(struct getdns_dict *dict, struct getdns_list **answer)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(dict != NULL && answer != NULL)
    {
        *answer = getdns_list_create();
        walkresultlist = *answer;

        twalk(dict->rootp, getdns_dict_visit);

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
    dict->rootp = NULL;

    return dict;
} /* getdns_dict_create */

/*---------------------------------------- getdns_dict_visit_copyitem */
/**
 * private function called by getdns_dict_copy() through the tree walk function 
 * is called as each node is visited.  twalk() calls 3x for each node and passes order
 * to tell us whether it is a pre/in/post order. We use this to copy the dictionary one item at
 * a time - this could be sped up
 */
void
getdns_dict_visit_copyitem(const void *node, VISIT order, int level)
{
    struct getdns_dict_item *item;

    item = *(struct getdns_dict_item **) node;
    /* postorder is mis-named - it results in in-order traversal */
    if(order == postorder || order == leaf)
    {
        switch(item->dtype)
        {
            case t_bindata:
                getdns_dict_set_bindata(walkresultdict, item->key, item->data.bindata);
                break;

            case t_dict:
                getdns_dict_set_dict(walkresultdict, item->key, item->data.dict);
                break;

            case t_int:
                getdns_dict_set_int(walkresultdict, item->key, item->data.n);
                break;

            case t_list:
                getdns_dict_set_list(walkresultdict, item->key, item->data.list);
                break;

            case t_invalid:
            default:
                // TODO: this is a fault of some kind, for now ignore it
                break;
        }
    }

    return;
} /* getdns_dict_visit_copyitem */

/*---------------------------------------- getdns_dict_copy */
/**
 * private function used to make a copy of a dict structure, the caller is responsible
 * for freeing storage allocated to returned value
 * NOTE: not thread safe - this needs to be fixed to be thread safe
 * @param srcdict the dictionary structure to copy
 * @return the address of the copy of the dictionary structure on success
 * @return NULL on error (out of memory, invalid srcdict)
 */
getdns_return_t
getdns_dict_copy(struct getdns_dict *srcdict, struct getdns_dict **dstdict)
{
    getdns_return_t retval = GETDNS_RETURN_NO_SUCH_DICT_NAME;

    if(srcdict != NULL && dstdict != NULL)
    {
        *dstdict = getdns_dict_create();
        walkresultdict = *dstdict;

        twalk(srcdict->rootp, getdns_dict_visit_copyitem);

        retval = GETDNS_RETURN_GOOD;
    }

    return retval;
} /* getdns_dict_copy */

/*---------------------------------------- getdns_dict_item_free */
/**
 * private function used to release storage associated with a dictionary item
 * @param all memory in this structure and its children will be freed
 * @return void
 */
void
getdns_dict_item_free(struct getdns_dict_item *item)
{
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
    struct getdns_dict_item keyitem;
    struct getdns_dict_item *item;

    if(dict != NULL && dict->rootp != NULL)
    {
        while(dict->rootp != NULL)
        {
            item = *((struct getdns_dict_item **) dict->rootp);
            keyitem.key = item->key;
            tdelete(&keyitem, &(dict->rootp), getdns_dict_cmp);
            getdns_dict_item_free(item);
        }

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
                item->data.bindata->data = (void *) malloc(item->data.bindata->size);
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

/*---------------------------------------- getdns_dict_visit_print */
/**
 * private function called by the tree walk function invoked by getdns_pretty_print_dict
 * it is called as each node is visited.  twalk() calls 3x for each node and passes order
 * to tell us whether it is a pre/in/post order
 * TODO: need to handle nested non-trivial data types
 */
void
getdns_dict_visit_print(const void *node, VISIT order, int level)
{
    struct getdns_dict_item *item;
    int    newlen;
    char   *dtypestr = NULL;
    char   *valstr   = NULL;
    char   *itemstr  = NULL;

    item = *(struct getdns_dict_item **) node;
    /* postorder is mis-named - it results in in-order traversal */
    if(order == postorder || order == leaf)
    {
        switch(item->dtype)
        {
            case t_bindata:
                dtypestr = "bindata";
                valstr = strdup("NOT IMPLEMENTED");
                break;

            case t_dict:
                dtypestr = "dict";
                valstr = strdup("NOT IMPLEMENTED");
                break;

            case t_int:
                dtypestr = "int";
                asprintf(&valstr, "%d", item->data.n);
                break;

            case t_list:
                dtypestr = "list";
                valstr = strdup("NOT IMPLEMENTED");
                break;

            case t_invalid:
            default:
                dtypestr = "invalid";
                valstr = strdup("");
                break;
        }

        newlen = asprintf(&itemstr, "key=\"%s\", type=\"%s\", value=\"%s\"\n", item->key, dtypestr, valstr);
        if(newlen != -1)
        {
            walkresultchar = (char *) realloc(walkresultchar, walkresultcharlen + newlen + 1);
            memcpy(walkresultchar + walkresultcharlen, itemstr, newlen);
            walkresultcharlen += newlen;
            walkresultchar[walkresultcharlen] = '\0';
        }
        // else
            // TODO: this is a fault - do something

        free(valstr);
    }

    return;
} /* getdns_dict_visit_print */

/*---------------------------------------- getdns_pretty_print_dict */
char *
getdns_pretty_print_dict(struct getdns_dict *dict)
{
    char *retval = NULL;

    walkresultcharlen = 0;
    walkresultchar    = NULL;

    if(dict != NULL && dict->rootp != NULL)
    {
        twalk(dict->rootp, getdns_dict_visit_print);
        if(walkresultcharlen > 0)
        {
            retval = strdup(walkresultchar);
            free(walkresultchar);
        }
    }

    return retval;
} /* getdns_pretty_print_dict */

/* getdns_dict.c */
