/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/

#ifndef _NIDS_NIDS_H
#define _NIDS_NIDS_H

#include "pcap.h"
#include "NETINET\IN_SYSTM.H"
#define LIBNET_LIL_ENDIAN 1

# ifdef __cplusplus
extern "C" {
# endif

# define NIDS_MAJOR 1
# define NIDS_MINOR 24

	enum NIDS_FLAG
	{
		NIDS_TCP_RETRANS = 1,
		NIDS_OUT_OF_ORDER = 2,
		NIDS_CHKSUM_FAIL = 4,
		NIDS_BAD_TCP_HEADER = 8,
		NIDS_BAD_UDP_HEADER = 16,
		NIDS_BAD_IP_HEADER = 32,
		NIDS_CHKSUM_OFFLOAD_DETECTED = 64

	};

	enum
	{
		NIDS_WARN_IP = 1,
		NIDS_WARN_TCP,
		NIDS_WARN_UDP,
		NIDS_WARN_SCAN
	};

	enum
	{
		NIDS_WARN_UNDEFINED = 0,
		NIDS_WARN_IP_OVERSIZED,
		NIDS_WARN_IP_INVLIST,
		NIDS_WARN_IP_OVERLAP,
		NIDS_WARN_IP_HDR,
		NIDS_WARN_IP_SRR,
		NIDS_WARN_TCP_TOOMUCH,
		NIDS_WARN_TCP_HDR,
		NIDS_WARN_TCP_BIGQUEUE,
		NIDS_WARN_TCP_BADFLAGS
	};

# define NIDS_JUST_EST 1
# define NIDS_DATA 2
# define NIDS_CLOSE 3
# define NIDS_RESET 4
# define NIDS_TIMED_OUT 5
# define NIDS_EXITING   6	/* nids is exiting; last chance to get data */

# ifdef ENABLE_TCPREASM
# define NIDS_RESUME 7
# endif

# define NIDS_DO_CHKSUM  0
# define NIDS_DONT_CHKSUM 1

#ifdef ENABLE_TCPREASM
# define NIDS_TCP_RESUME_NONE   0
# define NIDS_TCP_RESUME_CLIENT 1
# define NIDS_TCP_RESUME_SERVER 2
#endif
	
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_LOCAL0      (16<<3) /* reserved for local use */
#define HAVE_BSD_UDPHDR 1
#define LITTLE_ENDIAN 1234
#define BYTE_ORDER LITTLE_ENDIAN
	
#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif

	/* wireless frame types, mostly from tcpdump (wam) */
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define DATA_FRAME_IS_QOS(x)    ((x) & 0x08)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800

	#ifdef HAVE_LIBGTHREAD_2_0

#define START_CAP_QUEUE_PROCESS_THREAD() \
	if(nidsParams.multiproc) { /* threading... */ \
	if(!(g_thread_create_full((GThreadFunc)cap_queue_process_thread,NULL,0,FALSE,TRUE,G_THREAD_PRIORITY_LOW,&gerror))) { \
	strcpy(errBuf, "thread: "); \
	strncat(errBuf, gerror->message, sizeof(errBuf) - 8); \
	return 0; \
	}; \
	}

#define STOP_CAP_QUEUE_PROCESS_THREAD() \
	if(nidsParams.multiproc) { /* stop the capture process thread */ \
	g_async_queue_push(cap_queue,&EOF_item); \
	}


/* thread entry point 
* pops capture queue items and feeds them to
* the ip fragment processors - mcree
*/
static void cap_queue_process_thread()
{
	struct cap_queue_item *qitem;

	while(1) { /* loop "forever" */
		qitem=g_async_queue_pop(cap_queue);
		if (qitem==&EOF_item) break; /* EOF item received: we should exit */
		CallIpFragProcs(qitem->data, qitem->caplen, 0);
		free(qitem->data);
		free(qitem);
	}
	g_thread_exit(NULL);
}

#else

#define START_CAP_QUEUE_PROCESS_THREAD()
#define STOP_CAP_QUEUE_PROCESS_THREAD()

#endif

	struct psuedo_hdr
	{
		u_int saddr;      
		u_int daddr;      
		u_char zero;        
		u_char protocol;    
		u_short len;        
	};

	struct tuple4
	{
		u_short source;
		u_short dest;
		u_int saddr;
		u_int daddr;
	};

	struct half_stream
	{
		char state;
#ifdef ENABLE_TCPREASM
		char resume_second_half;
#endif
  
		char collect;
		char collect_urg;

		char *data;
		int offset;
		int count;
		int count_new;
		int bufsize;
		int rmem_alloc;

		int urg_count;
		u_int acked;
		u_int seq;
		u_int ack_seq;
		u_int first_data_seq;
		u_char urgdata;
		u_char count_new_urg;
		u_char urg_seen;
		u_int urg_ptr;
		u_short window;
		u_char ts_on;
		u_char wscale_on;
		u_int curr_ts; 
		u_int wscale;
		struct skbuff *list;
		struct skbuff *listtail;
	};

	struct tcp_stream
	{
		struct tuple4 addr;
		char nids_state;
		struct lurker_node *listeners;
		struct half_stream client;
		struct half_stream server;
		struct tcp_stream *next_node;
		struct tcp_stream *prev_node;
		int hash_index;
		struct tcp_stream *next_time;
		struct tcp_stream *prev_time;
		int read;
		struct tcp_stream *next_free;
		void *user;
	};

	struct nids_prm
	{
		int n_tcp_streams;
		int n_hosts;
		char *device;
		char *filename;
		int sk_buff_size;
		int dev_addon;
		void (*syslog) ();
		int syslog_level;
		int scan_num_hosts;
		int scan_delay;
		int scan_num_ports;
		void (*no_mem) (char *);
		int (*ip_filter) ();
		char *pcap_filter;
		int promisc;
		int one_loop_less;
		int pcap_timeout;
		int multiproc;
		int queue_limit;
		int tcp_workarounds;
		pcap_t *pcap_desc;
#ifdef ENABLE_TCPREASM
		int tcp_resume_wscale;
#endif
	};

	struct tcp_timeout
	{
		struct tcp_stream *a_tcp;
		struct timeval timeout;
		struct tcp_timeout *next;
		struct tcp_timeout *prev;
	};

	struct nids_chksum_ctl {
		u_int netaddr;
		u_int mask;
		u_int action;
		u_int reserved;
	};

extern int raw_init();

# ifdef __cplusplus
}
# endif

#endif /* _NIDS_NIDS_H */
