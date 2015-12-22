/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@icm.edu.pl>. All rights reserved.
See the file COPYING for license details.
*/

#pragma once

#include "nids.h"

#define IPF_NOTF 1
#define IPF_NEW  2
#define IPF_ISF  3

/*This class handles all things related to fragmentation at the IP layer.  For instance, it keeps
	track of previous fragments still waiting to be completed.

	Description of how fragments are tracked:  This class...
		has a linked list of hosts (hostfrags ** fragtable).  Each of those hosts
		has a linked list of packet fragment queues (ipq * hostfrags::ipqueue).  Each of those 'packet in progress' queues
		has a linked list of received contributions (ipfrag * hostfrags::ipqueue::fragments).

	Here's a comment from the linux version worth keeping: "This fragment handler is a bit of a heap. On the other
		hand it works quite happily and handles things quite well."

	The linux version had function pointers for no apparent reason other than to make things less obvious, so they are gone.
	The linux version had separate functions for adding and subtracting integers for no good reason, also now gone.
	The linux had hand-coded linked lists instead of STL, also now gone.
*/
class CIP_FragmentHandler
{
private:
	struct sk_buff {
		char *data;
		int truesize;
	};

	/* Describe an IP fragment. */
	struct ipfrag {
		int offset;			/* offset of fragment in IP datagram    */
		int end;			/* last byte of data in datagram        */
		int len;			/* length of this fragment              */
		sk_buff *skb;		/* complete received fragment           */
		unsigned char *ptr;		/* pointer into real fragment data      */
		ipfrag *next;		/* linked list pointers                 */
		ipfrag *prev;
	};

	struct hostfrags; //the following three structs are interdependent, so a forward declaration is needed.
	struct ipq;

	struct timer_list {
		timer_list *prev;
		timer_list *next;
		int expires;
		void (*function)(CIP_FragmentHandler *, ipq *);
		ipq * data;
	};

	/* Describe an entry in the "incomplete datagrams" queue. */
	struct ipq {
		unsigned char *mac;		/* pointer to MAC header                */
		struct ip *iph;		/* pointer to IP header                 */
		int len;			/* total length of original datagram    */
		short ihlen;			/* length of the IP header              */
		short maclen;			/* length of the MAC header             */
		timer_list timer;	/* when will this queue expire?         */
		ipfrag *fragments;	/* linked list of received fragments    */
		hostfrags *hf;
		ipq *next;		/* linked list pointers                 */
		ipq *prev;
	};

	struct hostfrags {
		ipq *ipqueue;
		int ip_frag_mem;
		u_int ip;
		int hash_index;
		hostfrags *prev;
		hostfrags *next;
	};

	int jiffies();
	void atomic_sub(int ile, int *co);
	void atomic_add(int ile, int *co);
	void panic(char *str);
	void add_timer(timer_list * x);
	void del_timer(timer_list * x);
	void kfree_skb(sk_buff * skb);
	void frag_kfree_skb(sk_buff * skb);
	void frag_kfree_s(void *ptr, int len);
	void * frag_kmalloc(int size);
	ipfrag * ip_frag_create(int offset, int end, sk_buff * skb, unsigned char *ptr);
	int frag_index(ip * iph);
	int hostfrag_find(ip * iph);
	void hostfrag_create(ip * iph);
	void rmthis_host();
	ipq * ip_find(ip * iph);
	void ip_free(ipq * qp);
	static void ip_expire(CIP_FragmentHandler * thisInstance, ipq *qp);
	void ip_evictor();
	ipq * ip_create(ip * iph);
	int ip_done(ipq * qp);
	char * ip_glue(ipq * qp);
	char * ip_defrag(ip *iph, sk_buff *skb, u_int * nidsFlags);

	hostfrags **fragtable;
	hostfrags *this_host;
	int numpack;
	int hash_size;
	int timenow;
	unsigned int time0;
	timer_list *timer_head, *timer_tail;

public:
	CIP_FragmentHandler();

	int ip_defrag_stub(ip *iph, ip **defrag, unsigned int * nidsFlags, nids_prm *nids_params);
	void ip_frag_init(int, nids_prm*);
	void ip_frag_exit();
	
};