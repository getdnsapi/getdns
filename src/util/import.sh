#!/bin/sh

REPO=http://unbound.net/svn/trunk

wget -O rbtree.c			${REPO}/util/rbtree.c
wget -O orig-headers/rbtree.h		${REPO}/util/rbtree.h
wget -O val_secalgo.c			${REPO}/validator/val_secalgo.c
wget -O orig-headers/val_secalgo.h	${REPO}/validator/val_secalgo.h
