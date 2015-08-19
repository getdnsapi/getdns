/*
 * rbtree.h -- generic red-black tree
 *
 * Copyright (c) 2001-2007, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file
 * Red black tree. Implementation taken from NSD 3.0.5, adjusted for use
 * in unbound (memory allocation, logging and so on).
 */

#ifndef UTIL_RBTREE_H_
#define	UTIL_RBTREE_H_

/**
 * This structure must be the first member of the data structure in
 * the rbtree.  This allows easy casting between an _getdns_rbnode_t and the
 * user data (poor man's inheritance).
 */
typedef struct _getdns_rbnode_t _getdns_rbnode_t;
/**
 * The _getdns_rbnode_t struct definition.
 */
struct _getdns_rbnode_t {
	/** parent in rbtree, RBTREE_NULL for root */
	_getdns_rbnode_t   *parent;
	/** left node (smaller items) */
	_getdns_rbnode_t   *left;
	/** right node (larger items) */
	_getdns_rbnode_t   *right;
	/** pointer to sorting key */
	const void *key;
	/** colour of this node */
	uint8_t	    color;
};

/** The nullpointer, points to empty node */
#define	RBTREE_NULL &_getdns_rbtree_null_node
/** the global empty node */
extern	_getdns_rbnode_t	_getdns_rbtree_null_node;

/** An entire red black tree */
typedef struct _getdns_rbtree_t _getdns_rbtree_t;
/** definition for tree struct */
struct _getdns_rbtree_t {
	/** The root of the red-black tree */
	_getdns_rbnode_t    *root;

	/** The number of the nodes in the tree */
	size_t       count;

	/** 
	 * Key compare function. <0,0,>0 like strcmp. 
	 * Return 0 on two NULL ptrs. 
	 */
	int (*cmp) (const void *, const void *);
};

/** 
 * Create new tree (malloced) with given key compare function. 
 * @param cmpf: compare function (like strcmp) takes pointers to two keys.
 * @return: new tree, empty.
 */
_getdns_rbtree_t *_getdns_rbtree_create(int (*cmpf)(const void *, const void *));

/** 
 * Init a new tree (malloced by caller) with given key compare function. 
 * @param rbtree: uninitialised memory for new tree, returned empty.
 * @param cmpf: compare function (like strcmp) takes pointers to two keys.
 */
void _getdns_rbtree_init(_getdns_rbtree_t *rbtree, int (*cmpf)(const void *, const void *));

/** 
 * Insert data into the tree. 
 * @param rbtree: tree to insert to.
 * @param data: element to insert. 
 * @return: data ptr or NULL if key already present. 
 */
_getdns_rbnode_t *_getdns_rbtree_insert(_getdns_rbtree_t *rbtree, _getdns_rbnode_t *data);

/**
 * Delete element from tree.
 * @param rbtree: tree to delete from.
 * @param key: key of item to delete.
 * @return: node that is now unlinked from the tree. User to delete it. 
 * returns 0 if node not present 
 */
_getdns_rbnode_t *_getdns_rbtree_delete(_getdns_rbtree_t *rbtree, const void *key);

/**
 * Find key in tree. Returns NULL if not found.
 * @param rbtree: tree to find in.
 * @param key: key that must match.
 * @return: node that fits or NULL.
 */
_getdns_rbnode_t *_getdns_rbtree_search(_getdns_rbtree_t *rbtree, const void *key);

/**
 * Find, but match does not have to be exact.
 * @param rbtree: tree to find in.
 * @param key: key to find position of.
 * @param result: set to the exact node if present, otherwise to element that
 *   precedes the position of key in the tree. NULL if no smaller element.
 * @return: true if exact match in result. Else result points to <= element,
 * or NULL if key is smaller than the smallest key. 
 */
int _getdns_rbtree_find_less_equal(_getdns_rbtree_t *rbtree, const void *key, 
	_getdns_rbnode_t **result);

/**
 * Returns first (smallest) node in the tree
 * @param rbtree: tree
 * @return: smallest element or NULL if tree empty.
 */
_getdns_rbnode_t *_getdns_rbtree_first(_getdns_rbtree_t *rbtree);

/**
 * Returns last (largest) node in the tree
 * @param rbtree: tree
 * @return: largest element or NULL if tree empty.
 */
_getdns_rbnode_t *_getdns_rbtree_last(_getdns_rbtree_t *rbtree);

/**
 * Returns next larger node in the tree
 * @param rbtree: tree
 * @return: next larger element or NULL if no larger in tree.
 */
_getdns_rbnode_t *_getdns_rbtree_next(_getdns_rbnode_t *rbtree);

/**
 * Returns previous smaller node in the tree
 * @param rbtree: tree
 * @return: previous smaller element or NULL if no previous in tree.
 */
_getdns_rbnode_t *_getdns_rbtree_previous(_getdns_rbnode_t *rbtree);

/**
 * Call with node=variable of struct* with _getdns_rbnode_t as first element.
 * with type is the type of a pointer to that struct. 
 */
#define RBTREE_FOR(node, type, rbtree) \
	for(node=(type)_getdns_rbtree_first(rbtree); \
		(_getdns_rbnode_t*)node != RBTREE_NULL; \
		node = (type)_getdns_rbtree_next((_getdns_rbnode_t*)node))

/**
 * Call function for all elements in the redblack tree, such that
 * leaf elements are called before parent elements. So that all
 * elements can be safely free()d.
 * Note that your function must not remove the nodes from the tree.
 * Since that may trigger rebalances of the rbtree.
 * @param tree: the tree
 * @param func: function called with element and user arg.
 * 	The function must not alter the rbtree.
 * @param arg: user argument.
 */
void _getdns_traverse_postorder(_getdns_rbtree_t* tree, void (*func)(_getdns_rbnode_t*, void*),
	void* arg);

#endif /* UTIL_RBTREE_H_ */
