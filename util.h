#pragma once
/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/

#ifndef _NIDS_UTIL_H
#define _NIDS_UTIL_H

#ifndef u_int
typedef unsigned int u_int;
#endif
#ifndef u_char
typedef unsigned char u_char;
#endif

#define mknew(x)	(x *)test_malloc(sizeof(x))
#define b_comp(x,y)	(!memcmp(&(x), &(y), sizeof(x)))

struct proc_node {
	void (*item)();
	struct proc_node *next;
	void *userParam;
};

struct lurker_node {
	void (*item)();
	void *data;
	char whatto;
	void *userParam;
	struct lurker_node *next;
};

void nids_no_mem(char *);
char *test_malloc(int);
void register_callback(struct proc_node **procs, void (*x), void *info = 0 );
void unregister_callback(struct proc_node **procs, void (*x), void *info = 0 );

static __inline int before(u_int seq1, u_int seq2) {
	return ((int)(seq1 - seq2) < 0);
}

static __inline int after(u_int seq1, u_int seq2)
{
	return ((int)(seq2 - seq1) < 0);
}

#endif /* _NIDS_UTIL_H */
