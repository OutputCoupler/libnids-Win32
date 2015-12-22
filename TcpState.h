/*
    Developed for the NSITE program for the US Army at AMRDEC.
    Copyright (c) 2012 William McGloon <output.coupler@gmail.com>
*/

/*
    This file is part of libnids.

    libnids is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    libnids is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libnids.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "config.h"
#include "nids.h"
#include "util.h"
#include "NETINET\IP.H"
#include "NETINET\IP_ICMP.H"
#include "NETINET\TCP.H"
#include "Scanner.h"

struct skbuff {
	struct skbuff *next;
	struct skbuff *prev;

	void *data;
	u_int len;
	u_int truesize;
	u_int urg_ptr;

	char fin;
	char urg;
	u_int seq;
	u_int ack;
};

#if ! HAVE_TCP_STATES

	enum {
		TCP_ESTABLISHED = 1,
		TCP_SYN_SENT,
		TCP_SYN_RECV,
		TCP_FIN_WAIT1,
		TCP_FIN_WAIT2,
		TCP_TIME_WAIT,
		TCP_CLOSE,
		TCP_CLOSE_WAIT,
		TCP_LAST_ACK,
		TCP_LISTEN,
		TCP_CLOSING			/* now a valid state */
	};

#endif

#define FIN_SENT 120
#define FIN_CONFIRMED 121
#define COLLECT_cc 1
#define COLLECT_sc 2
#define COLLECT_ccu 4
#define COLLECT_scu 8



#if HAVE_ICMPHDR
	#define STRUCT_ICMP icmphdr
	#define ICMP_CODE   code
	#define ICMP_TYPE   type
#else
	#define STRUCT_ICMP icmp
	#define ICMP_CODE   icmp_code
	#define ICMP_TYPE   icmp_type
#endif

#ifndef ICMP_DEST_UNREACH
	#define ICMP_DEST_UNREACH ICMP_UNREACH
	#define ICMP_PROT_UNREACH ICMP_UNREACH_PROTOCOL
	#define ICMP_PORT_UNREACH ICMP_UNREACH_PORT
	#define NR_ICMP_UNREACH   ICMP_MAXTYPE
#endif		

class CTcpState
{
public:
	CTcpState(nids_prm*, CScanner*);
	~CTcpState(void);

	void ReInit(nids_prm *, CScanner*);
	void Exit();
	
	void ProcessTcp(UCHAR *, int, UINT *);
	void ProcessIcmp(UCHAR *, UINT * );

	void TcpQueue(tcp_stream *, tcphdr *, half_stream *, half_stream *, char *, int, int, UINT *);
	void PruneQueue(half_stream *, tcphdr *);
	void PurgeQueue(half_stream *);
	
	void AddTcpClosingTimeout(tcp_stream *);
	void DelTcpClosingTimeout(tcp_stream *);
	void CheckTcpTimeouts(timeval *);

	int MakeHashIndex(tuple4);
	
	int GetTs(tcphdr *, UINT *);
	int GetWscale(tcphdr *, UINT *);
	
	void AddFromSkb(tcp_stream *, half_stream *, half_stream *, UCHAR *, int, UINT, char, char, UINT);
	void AddNewTcp(tcphdr *, ip *);
	void add2buf(half_stream *, char *, int);
	
	void RideLurkers(tcp_stream *, char);
	void NotifyListeners(tcp_stream *, half_stream *);
	
	void HandleAck(half_stream *, UINT);
	tcp_stream * FindStream(tcphdr *, ip *, int *);
	tcp_stream * FindStream(tuple4 *);
	void FreeStream(tcp_stream *); 

	void Discard(tcp_stream *, int);
	void RegisterTcp(void (*x), void *);
	void UnregisterTcp(void (*x), void *);

	void SetLastPcapHeader(pcap_pkthdr *header) { lastPcapHeader = header; }

	static int ExpSeq(half_stream* sndStream, half_stream* rcvStream) { return sndStream->first_data_seq + rcvStream->count + rcvStream->urg_count; }

	int IsWhitelisted(unsigned int ip);

	u_short Checksum(struct tcphdr *th, int len, u_int saddr, u_int daddr);

	void SetChecksumWhitelist(nids_chksum_ctl *whitelist, int size) { checksumWhitelist = whitelist; whitelistSize = size; }

private:
	nids_chksum_ctl * checksumWhitelist;
	int whitelistSize;

	CScanner *scanner;
	nids_prm *nidsParams;
	proc_node *tcpProcs;

	pcap_pkthdr *lastPcapHeader;
	tcp_stream *tcpLatest, *tcpOldest, *freeStreams;
	tcp_stream *streamPool;
	tcp_stream **tcpStreamTable;
	tcp_timeout *nidsTcpTimeouts;
	
	ip *uglyIpHeader;

	int tcpStreamTableSize;
	int maxStream;
	int tcpNum;	

	bool initialized;

#ifdef ENABLE_TCPREASM
public:
	tcp_stream * InitiateTcpResume(tcphdr *, ip *, int);
	void NidsRegisterTcpResume(void (*x), void *);
	void NidsUnregisterTcpResume(void (*x), void *);

private:
	proc_node *tcpResumeProcs;
#endif
};

