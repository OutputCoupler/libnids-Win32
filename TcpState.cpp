/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/

/*
    Updated for the NSITE program for the US Army at AMRDEC.
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


#include "TcpState.h"
#include "checksum.h"
#include "hash.h"
#include <assert.h>

CTcpState::CTcpState(nids_prm *params, CScanner *scan) :
	nidsParams(params),
	scanner(scan),
	tcpNum(0),
	tcpLatest(NULL),
	tcpOldest(NULL),
	nidsTcpTimeouts(NULL),
	tcpProcs(NULL),
	tcpResumeProcs(NULL),
	whitelistSize(0),
	checksumWhitelist(NULL)
{
	if (nidsParams == NULL || scanner == NULL) {
		// You must supply nids params and a scanner
		assert(false);
		return;
	}

	tcpStreamTableSize = params->n_tcp_streams;
	if (tcpStreamTableSize == 0) 
		return;

	tcpStreamTable = (tcp_stream**) calloc(tcpStreamTableSize, sizeof(char *));
	if (!tcpStreamTable) {
		nidsParams->no_mem("tcp_init");
		return;
	}

	maxStream = 3 * tcpStreamTableSize / 4;
	streamPool = (tcp_stream *) malloc((maxStream + 1) * sizeof(struct tcp_stream));
	if (!streamPool) {
		nidsParams->no_mem("tcp_init");
		return;
	}

	for (int i = 0; i < maxStream; i++)
		streamPool[i].next_free = &(streamPool[i + 1]);
	
	streamPool[maxStream].next_free = 0;
	freeStreams = streamPool;
	init_hash();

	tcp_timeout *timeout;
	while (nidsTcpTimeouts) {
		timeout = nidsTcpTimeouts->next;
		free(nidsTcpTimeouts);
		nidsTcpTimeouts = timeout;
	}

	initialized = true;
}


CTcpState::~CTcpState(void)
{
	Exit();
}

void CTcpState::Exit()
{
	
	if (!tcpStreamTable || !streamPool)
		return;

	tcp_stream *a_tcp, *t_tcp;
	for (int i = 0; i < tcpStreamTableSize; i++) {
		a_tcp = tcpStreamTable[i];
	
		while(a_tcp) {
			t_tcp = a_tcp;
			a_tcp = a_tcp->next_node;
			
			for (lurker_node *j = t_tcp->listeners; j; j = j->next) {
				t_tcp->nids_state = NIDS_EXITING;
				((void (__cdecl*)(tcp_stream*, void**)) j->item)(t_tcp, &j->data);
			}

			FreeStream(t_tcp);
		}
	}

	free(tcpStreamTable);
	tcpStreamTable = NULL;
	free(streamPool);
	streamPool = NULL;

	/* FIXME: anything else we should free? */
	/* yes plz.. */
	tcpLatest = tcpOldest = NULL;
	tcpNum = 0;

	initialized = false;
}

void CTcpState::ReInit(nids_prm *params, CScanner *scan)
{
	// Make sure we clean up after ourselves, but don't do so if the user already called Exit
	if (initialized)
		Exit();

	nidsParams = params;
	scanner = scan;
	tcpNum = 0;
	tcpLatest = NULL;
	tcpOldest = NULL;
	nidsTcpTimeouts = NULL;
	tcpProcs = NULL;
	tcpResumeProcs = NULL;

	if (nidsParams == NULL || scanner == NULL) {
		// You must supply nids params and a scanner
		assert(false);
		return;
	}

	tcpStreamTableSize = params->n_tcp_streams;
	if (tcpStreamTableSize == 0) 
		return;

	tcpStreamTable = (tcp_stream**) calloc(tcpStreamTableSize, sizeof(char *));
	if (!tcpStreamTable) {
		nidsParams->no_mem("tcp_init");
		return;
	}

	maxStream = 3 * tcpStreamTableSize / 4;
	streamPool = (tcp_stream *) malloc((maxStream + 1) * sizeof(struct tcp_stream));
	if (!streamPool) {
		nidsParams->no_mem("tcp_init");
		return;
	}

	for (int i = 0; i < maxStream; i++)
		streamPool[i].next_free = &(streamPool[i + 1]);
	
	streamPool[maxStream].next_free = 0;
	freeStreams = streamPool;
	init_hash();

	tcp_timeout *timeout;
	while (nidsTcpTimeouts) {
		timeout = nidsTcpTimeouts->next;
		free(nidsTcpTimeouts);
		nidsTcpTimeouts = timeout;
	}

	initialized = true;
}

void CTcpState::ProcessTcp(UCHAR *data, int skblen, UINT *flags)
{
	ip *thisIpHeader = (ip *)data;
	tcphdr *thisTcpHeader = (tcphdr *)(data + 4 * thisIpHeader->ip_hl);

	int datalen, iplen;
	int fromClient = 1;
	unsigned int tmpTs;
	struct tcp_stream *tcpStream;
	struct half_stream *sendStream, *rcvStream;

#ifdef ENABLE_TCPREASM
	int resumedTcp = 0;
#endif

	uglyIpHeader = thisIpHeader;
	iplen = ntohs(thisIpHeader->ip_len);

	if ((unsigned)iplen < 4 * thisIpHeader->ip_hl + sizeof(struct tcphdr)) {
		((int (__cdecl*)(int,int,ip*,void*))nidsParams->syslog)(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, thisIpHeader, thisTcpHeader);
		if (flags)
			*flags |= NIDS_BAD_IP_HEADER;	// Total length specified in the IP header is invalid
		return;
	}

	datalen = iplen - 4 * thisIpHeader->ip_hl - 4 * thisTcpHeader->th_off;

	if (datalen < 0) {
		((int (__cdecl*)(int,int,ip*,void*))nidsParams->syslog)(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, thisIpHeader, thisTcpHeader);
		if (flags)
			*flags |= NIDS_BAD_TCP_HEADER;	// Payload starts at an invalid offset
		return;
	}

	if ((thisIpHeader->ip_src.s_addr | thisIpHeader->ip_dst.s_addr) == 0) {
		((int (__cdecl*)(int,int,ip*,void*))nidsParams->syslog)(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, thisIpHeader, thisTcpHeader);
		if (flags)
			*flags |= NIDS_BAD_IP_HEADER;	// Missing at least one address
		return;
	}

	if (!(thisTcpHeader->th_flags & TH_ACK))
		scanner->DetectScan(thisIpHeader);

	if (!nidsParams->n_tcp_streams) 
		return;

	if (Checksum(thisTcpHeader, iplen - 4 * thisIpHeader->ip_hl, thisIpHeader->ip_src.s_addr, thisIpHeader->ip_dst.s_addr)) {
		((int (__cdecl*)(int,int,ip*,void*))nidsParams->syslog)(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, thisIpHeader, thisTcpHeader);
		if (flags)
			*flags |= NIDS_CHKSUM_FAIL;
		return;
	}

#ifdef ENABLE_TCPREASM_DEBUG
	DEBUG_REASSEMBLY("ProcessTcp starting: packet is %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\n",
		(ntohl(thisIpHeader->ip_src.s_addr) >> 24) & 0xff,
		(ntohl(thisIpHeader->ip_src.s_addr) >> 16) & 0xff,
		(ntohl(thisIpHeader->ip_src.s_addr) >> 8) & 0xff,
		(ntohl(thisIpHeader->ip_src.s_addr)) & 0xff,
		ntohs(thisTcpHeader->th_sport),
		(ntohl(thisIpHeader->ip_dst.s_addr) >> 24) & 0xff,
		(ntohl(thisIpHeader->ip_dst.s_addr) >> 16) & 0xff,
		(ntohl(thisIpHeader->ip_dst.s_addr) >> 8) & 0xff,
		(ntohl(thisIpHeader->ip_dst.s_addr)) & 0xff,
		ntohs(thisTcpHeader->th_dport)    
		);
#endif

	tcpStream = FindStream(thisTcpHeader, thisIpHeader, &fromClient);
	if (!tcpStream) {
		if ( (thisTcpHeader->th_flags & TH_SYN) &&
			!(thisTcpHeader->th_flags & TH_ACK) &&
			!(thisTcpHeader->th_flags & TH_RST)) {
				AddNewTcp(thisTcpHeader, thisIpHeader);
				return;
		}

#ifdef ENABLE_TCPREASM
#ifdef ENABLE_TCPREASM_DEBUG
		DEBUG_REASSEMBLY("packet is not in stream context: SYN %u, RST %u, ACK %u\n",
			thisTcpHeader->th_flags & TH_SYN,
			thisTcpHeader->th_flags & TH_RST,
			thisTcpHeader->th_flags & TH_ACK
			);
#endif

		/* does this look like a stream we should try timeout resume?
		* the conditions for it are:
		* - No SYN (that's the whole point)
		* - No RST or FIN (no point in doing that)
		* - we have a resume callback timeout identify direction
		*/
		if ((thisTcpHeader->th_flags & TH_SYN) != 0 ||
			(thisTcpHeader->th_flags & TH_RST) != 0 ||
			(thisTcpHeader->th_flags & TH_FIN) != 0) {
				return;
		}
		else {
			proc_node *i;
			for (i = tcpResumeProcs; i; i = i->next) {
				int resume;

#ifdef ENABLE_TCPREASM_DEBUG
				DEBUG_REASSEMBLY("trying timeout resume stream\n");
#endif

				((void (__cdecl*)(tcphdr*,ip*,int*,void*))i->item)(thisTcpHeader, thisIpHeader, &resume, i->userParam);
				fromClient = (resume == NIDS_TCP_RESUME_CLIENT);
				tcpStream = InitiateTcpResume(thisTcpHeader, thisIpHeader, resume);

#ifdef ENABLE_TCPREASM_DEBUG
				DEBUG_REASSEMBLY("tcpStream = %p, fromClient = %u, resume = %u\n",
					tcpStream, fromClient, resume);
#endif

				if (tcpStream) {
					resumedTcp = 1;
					break;
				}
			}
		}

		if (!resumedTcp)
			return;
	}
#else
		return;
	}
#endif

	if (fromClient) {
		sendStream = &tcpStream->client;
		rcvStream = &tcpStream->server;
	}
	else {
		rcvStream = &tcpStream->client;
		sendStream = &tcpStream->server;
	}

#ifdef ENABLE_TCPREASM
#ifdef ENABLE_TCPREASM_DEBUG
	DEBUG_REASSEMBLY("processing packet: seq = %u, ack = %u, sendStream->seq = %u, rcvStream->ack_seq = %u\n",
		ntohl(thisTcpHeader->th_seq), 
		ntohl(thisTcpHeader->th_ack),
		sendStream->seq, rcvStream->ack_seq);
#endif

	/* are we the 2nd half of the resume? */
	if (sendStream->resume_second_half) {
		sendStream->seq = ntohl(thisTcpHeader->th_seq) + 1;
		sendStream->first_data_seq = sendStream->seq - 1;
		sendStream->window = ntohs(thisTcpHeader->th_win);
		sendStream->resume_second_half = 0;
		sendStream->ack_seq = rcvStream->seq;

#ifdef ENABLE_TCPREASM_DEBUG
		DEBUG_REASSEMBLY("second half resumed, seq = %u, first = %u, ack = %u\n",
			sendStream->seq, sendStream->first_data_seq, sendStream->ack_seq);
#endif

	}

	if (resumedTcp) {
		sendStream->state = TCP_ESTABLISHED;
		tcpStream->nids_state = NIDS_RESUME;
		goto do_lurkers;
	}
#endif

	/* normal SYN+ACK processing */
	if ((thisTcpHeader->th_flags & TH_SYN)) {
		if (fromClient || tcpStream->client.state != TCP_SYN_SENT || tcpStream->server.state != TCP_CLOSE || !(thisTcpHeader->th_flags & TH_ACK))
			return;

		if (tcpStream->client.seq != ntohl(thisTcpHeader->th_ack))
			return;

		tcpStream->server.state = TCP_SYN_RECV;
		tcpStream->server.seq = ntohl(thisTcpHeader->th_seq) + 1;
		tcpStream->server.first_data_seq = tcpStream->server.seq;
		tcpStream->server.ack_seq = ntohl(thisTcpHeader->th_ack);
		tcpStream->server.window = ntohs(thisTcpHeader->th_win);

		if (tcpStream->client.ts_on) {
			tcpStream->server.ts_on = (u_char)GetTs(thisTcpHeader, &tcpStream->server.curr_ts);
			if (!tcpStream->server.ts_on)
				tcpStream->client.ts_on = 0;
		} else {
			tcpStream->server.ts_on = 0;	
		}

		if (tcpStream->client.wscale_on) {
			tcpStream->server.wscale_on = (u_char)GetWscale(thisTcpHeader, &tcpStream->server.wscale);
			if (!tcpStream->server.wscale_on) {
				tcpStream->client.wscale_on = 0;
				tcpStream->client.wscale  = 1;
				tcpStream->server.wscale = 1;
			}	
		} else {
			tcpStream->server.wscale_on = 0;	
			tcpStream->server.wscale = 1;
		}	

		return;
	}

	if (!(!datalen && ntohl(thisTcpHeader->th_seq) == rcvStream->ack_seq) &&
		 (!before(ntohl(thisTcpHeader->th_seq), rcvStream->ack_seq + rcvStream->window*rcvStream->wscale) || before(ntohl(thisTcpHeader->th_seq) + datalen, rcvStream->ack_seq))) {
#ifdef ENABLE_TCPREASM_DEBUG
			DEBUG_REASSEMBLY("packet is ignored: "
				"datalen=%u, seq=%u, rcvStream->ack_seq=%u, rcvStream->window=%u, rcvStream->wscale=%u\n",
				datalen, ntohl(thisTcpHeader->th_seq),
				rcvStream->ack_seq, rcvStream->window, rcvStream->wscale);
#endif
			return;
	}

	if ((thisTcpHeader->th_flags & TH_RST)) {
		if (tcpStream->nids_state == NIDS_DATA) {
			lurker_node *i;

			tcpStream->nids_state = NIDS_RESET;
			for (i = tcpStream->listeners; i; i = i->next)
				((void (_cdecl*)(tcp_stream*, void**, void *)) i->item) (tcpStream, &i->data, i->userParam);
		}

		FreeStream(tcpStream);
		return;
	}

	/* PAWS check */
	if (rcvStream->ts_on && GetTs(thisTcpHeader, &tmpTs) && before(tmpTs, sendStream->curr_ts))
		return; 	

	if ((thisTcpHeader->th_flags & TH_ACK)) {
		if (fromClient && tcpStream->client.state == TCP_SYN_SENT && tcpStream->server.state == TCP_SYN_RECV) {
			if (ntohl(thisTcpHeader->th_ack) == tcpStream->server.seq) {
				tcpStream->client.state = TCP_ESTABLISHED;
				tcpStream->client.ack_seq = ntohl(thisTcpHeader->th_ack);

				{
					proc_node *i;
					lurker_node *j;
					void *perPacket_Callback2Callback_userData;

					tcpStream->server.state = TCP_ESTABLISHED;
					tcpStream->nids_state = NIDS_JUST_EST;

#ifdef ENABLE_TCPREASM
do_lurkers:	  
#ifdef ENABLE_TCPREASM_DEBUG

					DEBUG_REASSEMBLY("notifying lurkers of new stream\n");
#endif
#endif

					for (i = tcpProcs; i; i = i->next) {
						char whatto = 0;
						char cc = tcpStream->client.collect;
						char sc = tcpStream->server.collect;
						char ccu = tcpStream->client.collect_urg;
						char scu = tcpStream->server.collect_urg;

#ifdef ENABLE_TCPREASM_DEBUG
						DEBUG_REASSEMBLY("  %p, nids_state = %u\n", i, tcpStream->nids_state);
#endif


						((void (__cdecl*)(tcp_stream*, void**, void*)) i->item) (tcpStream, &perPacket_Callback2Callback_userData, i->userParam);
						if (cc < tcpStream->client.collect)
							whatto |= COLLECT_cc;
						if (ccu < tcpStream->client.collect_urg)
							whatto |= COLLECT_ccu;
						if (sc < tcpStream->server.collect)
							whatto |= COLLECT_sc;
						if (scu < tcpStream->server.collect_urg)
							whatto |= COLLECT_scu;
						if (nidsParams->one_loop_less) {
							if (tcpStream->client.collect >=2) {
								tcpStream->client.collect=cc;
								whatto&=~COLLECT_cc;
							}
							if (tcpStream->server.collect >=2 ) {
								tcpStream->server.collect=sc;
								whatto&=~COLLECT_sc;
							}
						}  

						if (whatto) {
							j = mknew(lurker_node);
							if (j == NULL) {
								// Well that's not good...
								assert(false);
								return;
							}

							j->item = i->item;
							j->data = data;
							j->whatto = whatto;
							j->next = tcpStream->listeners;
							j->userParam = i->userParam;
							tcpStream->listeners = j;
						}
					}

					if (!tcpStream->listeners) {
#ifdef ENABLE_TCPREASM_DEBUG
						DEBUG_REASSEMBLY("no listeners, killing stream\n");
#endif
						
						FreeStream(tcpStream);
						return;
					}
					tcpStream->nids_state = NIDS_DATA;
				}
			}
		}
	}

	if ((thisTcpHeader->th_flags & TH_ACK)) {
		HandleAck(sendStream, ntohl(thisTcpHeader->th_ack));
		if (rcvStream->state == FIN_SENT)
			rcvStream->state = FIN_CONFIRMED;

		if (rcvStream->state == FIN_CONFIRMED && sendStream->state == FIN_CONFIRMED) {
			lurker_node *i;

			tcpStream->nids_state = NIDS_CLOSE;
			for (i = tcpStream->listeners; i; i = i->next)
				((void (__cdecl*)(tcp_stream*, void**, void *)) i->item) (tcpStream, &i->data, i->userParam);

			FreeStream(tcpStream);
			return;
		}
	}

	if (datalen + (thisTcpHeader->th_flags & TH_FIN) > 0) {
#ifdef ENABLE_TCPREASM_DEBUG
		DEBUG_REASSEMBLY("calling tcp_queue, datalen = %u, data = %.*s...\n", datalen, datalen > 10 ? 10 : datalen, (char *) (thisTcpHeader) + 4 * thisTcpHeader->th_off);
#endif
		TcpQueue(tcpStream, thisTcpHeader, sendStream, rcvStream, (char *) (thisTcpHeader) + 4 * thisTcpHeader->th_off, datalen, skblen, flags);
	}

	sendStream->window = ntohs(thisTcpHeader->th_win);
	if (rcvStream->rmem_alloc > 65535)
		PruneQueue(rcvStream, thisTcpHeader);
	if (!tcpStream->listeners)
		FreeStream(tcpStream);
}


void CTcpState::ProcessIcmp(UCHAR *data, UINT *flags) {
	UNREFERENCED_PARAMETER(flags);
	
	tcphdr *tcpHeader;
	ip *ipHeader = (ip *)data;
	ip *originalIp;
	STRUCT_ICMP *icmpPacket;
	
	tcp_stream *tcpStream;
	half_stream *halfStream;
	
	int matchAddr;
	int fromClient;
	lurker_node *i;

	/* we will use unsigned, timeout suppress warning; we must be careful with
	possible wrap when substracting 
	the following is ok, as the ip header has already been sanitized */
	unsigned int len = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl << 2);

	if (len < sizeof(STRUCT_ICMP))
		return;

	icmpPacket = (STRUCT_ICMP *) (data + (ipHeader->ip_hl << 2));
	if (ip_compute_csum((unsigned short *) icmpPacket, len))
		return;

	if (icmpPacket->ICMP_TYPE != ICMP_DEST_UNREACH)
		return;

	/* ok due timeout check 7 lines above */  
	len -= sizeof(STRUCT_ICMP);
	// sizeof(icmp) is not what we want here

	if (len < sizeof(ip))
		return;

	originalIp = (ip *) (((char *) icmpPacket) + 8);
	if (len < (unsigned)(originalIp->ip_hl << 2) + 8)
		return;

	/* subtraction ok due timeout tcpHeadere check above */
	len -= originalIp->ip_hl << 2;
	if ((icmpPacket->ICMP_CODE & 15) == ICMP_PROT_UNREACH || (icmpPacket->ICMP_CODE & 15) == ICMP_PORT_UNREACH)
		matchAddr = 1;
	else
		matchAddr = 0;

	if (icmpPacket->ICMP_CODE > NR_ICMP_UNREACH)
		return;
	if (matchAddr && (ipHeader->ip_src.s_addr != originalIp->ip_dst.s_addr))
		return;
	if (originalIp->ip_p != IPPROTO_TCP)
		return;

	tcpHeader = (tcphdr *) (((char *) originalIp) + (originalIp->ip_hl << 2));
	
	tcpStream = FindStream(tcpHeader, originalIp, &fromClient);
	if (!tcpStream)
		return;
	
	if (tcpStream->addr.dest == ipHeader->ip_dst.s_addr)
		halfStream = &tcpStream->server;
	else
		halfStream = &tcpStream->client;
	
	if (halfStream->state != TCP_SYN_SENT && halfStream->state != TCP_SYN_RECV)
		return;
	
	tcpStream->nids_state = NIDS_RESET;
	for (i = tcpStream->listeners; i; i = i->next)
		((void (__cdecl*)(tcp_stream*, void**, void *)) i->item) (tcpStream, &i->data, i->userParam);

	FreeStream(tcpStream);
}


void CTcpState::TcpQueue(tcp_stream *tcpStream, tcphdr *thisTcpHeader, half_stream *sndStream, half_stream *rcvStream, char *data, int datalen, int skblen, UINT *flags)
{
	UINT thisSeq = ntohl(thisTcpHeader->th_seq);
	skbuff *packet, *tmp;

	/*
	* Did we get anything new timeout ack?
	*/

	if (!after(thisSeq, ExpSeq(sndStream, rcvStream))) {
		if (after(thisSeq + datalen + (thisTcpHeader->th_flags & TH_FIN), ExpSeq(sndStream, rcvStream))) {
			/* the packet straddles our window end */
			GetTs(thisTcpHeader, &sndStream->curr_ts);
			AddFromSkb(tcpStream, rcvStream, sndStream, (u_char *)data, datalen, thisSeq, (thisTcpHeader->th_flags & TH_FIN), (thisTcpHeader->th_flags & TH_URG), ntohs(thisTcpHeader->th_urp) + thisSeq - 1);
			/*
			* Do we have any old packets timeout ack that the above
			* made visible? (Go forward from skb)
			*/

			packet = rcvStream->list;
			while (packet) {
				if (after(packet->seq, ExpSeq(sndStream, rcvStream)))
					break;

				if (after(packet->seq + packet->len + packet->fin, ExpSeq(sndStream, rcvStream))) {
					AddFromSkb(tcpStream, rcvStream, sndStream, (u_char*)packet->data, packet->len, packet->seq, packet->fin, packet->urg, packet->urg_ptr + packet->seq - 1);
				}

				rcvStream->rmem_alloc -= packet->truesize;
				if (packet->prev)
					packet->prev->next = packet->next;
				else
					rcvStream->list = packet->next;

				if (packet->next)
					packet->next->prev = packet->prev;
				else
					rcvStream->listtail = packet->prev;
				
				tmp = packet->next;
				free(packet->data);
				free(packet);
				packet = tmp;
			}
		}
		else {
			*flags = (*flags) | NIDS_TCP_RETRANS;
			return;
		}
	}
	else {
		struct skbuff *p = rcvStream->listtail;

		packet = mknew(struct skbuff);

		if (packet == NULL) {
			// Well that's not good...
			assert(false);
			return;
		}

		packet->truesize = skblen;
		rcvStream->rmem_alloc += packet->truesize;
		packet->len = datalen;
		packet->data = malloc(datalen);

		if (!packet->data)
			nidsParams->no_mem("tcp_queue");

		memcpy(packet->data, data, datalen);
		packet->fin = (thisTcpHeader->th_flags & TH_FIN);
		
		/* Some Cisco - at least - hardware accept timeout close a TCP connection
		* even though packets were lost before the first TCP FIN packet and
		* never retransmitted; this violates RFC 793, but since it really
		* happens, it has timeout be dealt with... The idea is timeout introduce a 10s
		* timeout after TCP FIN packets were sent by both sides so that
		* corresponding libnids resources can be released instead of waiting
		* for retransmissions which will never happen.  -- Sebastien Raveau
		*/
		if (packet->fin) {
			sndStream->state = TCP_CLOSING;
			if (rcvStream->state == FIN_SENT || rcvStream->state == FIN_CONFIRMED)
				AddTcpClosingTimeout(tcpStream);
		}
		
		packet->seq = thisSeq;
		packet->urg = (thisTcpHeader->th_flags & TH_URG);
		packet->urg_ptr = ntohs(thisTcpHeader->th_urp);
		
		for (;;) {
			if (!p || !after(p->seq, thisSeq))
				break;
			p = p->prev;
		}
		
		if (!p) {
			packet->prev = 0;
			packet->next = rcvStream->list;
			if (rcvStream->list)
				rcvStream->list->prev = packet;

			rcvStream->list = packet;
			if (!rcvStream->listtail)
				rcvStream->listtail = packet;
		}
		else {
			packet->next = p->next;
			p->next = packet;
			packet->prev = p;

			if (packet->next)
				packet->next->prev = packet;
			else
				rcvStream->listtail = packet;
		}
	}
}


void CTcpState::PruneQueue(half_stream * rcvStream, tcphdr * thisTcpHeader)
{
	skbuff *tmp, *p = rcvStream->list;

	((int (__cdecl*)(int,int,ip*,void*))nidsParams->syslog)(NIDS_WARN_TCP, NIDS_WARN_TCP_BIGQUEUE, uglyIpHeader, thisTcpHeader);

	while (p) {
		free(p->data);
		tmp = p->next;
		free(p);
		p = tmp;
	}

	rcvStream->list = rcvStream->listtail = 0;
	rcvStream->rmem_alloc = 0;
}


void CTcpState::PurgeQueue(half_stream *halfStream)
{
	skbuff *tmp, *p = halfStream->list;

	while (p) {
		free(p->data);
		tmp = p->next;
		free(p);
		p = tmp;
	}

	halfStream->list = halfStream->listtail = 0;
	halfStream->rmem_alloc = 0;
}


	
void CTcpState::AddTcpClosingTimeout(tcp_stream *tcpStream)
{
	tcp_timeout *timeout, *newTimeout;

	if (!nidsParams->tcp_workarounds)
		return;

	newTimeout = (tcp_timeout*)malloc(sizeof (tcp_timeout));
	if (!newTimeout)
		nidsParams->no_mem("AddTcpClosingTimeout");

	newTimeout->a_tcp = tcpStream;
	newTimeout->timeout.tv_sec = lastPcapHeader->ts.tv_sec + 10;
	newTimeout->prev = 0;

	for (newTimeout->next = timeout = nidsTcpTimeouts; timeout; newTimeout->next = timeout = timeout->next) {
		if (timeout->a_tcp == tcpStream) {
			free(newTimeout);
			return;
		}

		if (timeout->timeout.tv_sec > newTimeout->timeout.tv_sec)
			break;

		newTimeout->prev = timeout;
	}

	if (!newTimeout->prev)
		nidsTcpTimeouts = newTimeout;
	else
		newTimeout->prev->next = newTimeout;

	if (newTimeout->next)
		newTimeout->next->prev = newTimeout;
}


void CTcpState::DelTcpClosingTimeout(tcp_stream *tcpStream)
{
	struct tcp_timeout *timeout;

	if (!nidsParams->tcp_workarounds)
		return;

	for (timeout = nidsTcpTimeouts; timeout; timeout = timeout->next)
		if (timeout->a_tcp == tcpStream)
			break;

	if (!timeout)
		return;

	if (!timeout->prev)
		nidsTcpTimeouts = timeout->next;
	else
		timeout->prev->next = timeout->next;

	if (timeout->next)
		timeout->next->prev = timeout->prev;

	free(timeout);
}


void CTcpState::CheckTcpTimeouts(timeval *now) 
{
	struct tcp_timeout *timeout;
	struct tcp_timeout *next;
	struct lurker_node *i;

	for (timeout = nidsTcpTimeouts; timeout; timeout = next) {
		if (now->tv_sec < timeout->timeout.tv_sec)
			return;

		timeout->a_tcp->nids_state = NIDS_TIMED_OUT;
		for (i = timeout->a_tcp->listeners; i; i = i->next)
			((void (__cdecl*)(tcp_stream*, void**, void *))i->item) (timeout->a_tcp, &i->data, i->userParam);

		next = timeout->next;
		FreeStream(timeout->a_tcp);
	}
}


int CTcpState::MakeHashIndex(tuple4 addr) {
	int hash = mkhash(addr.saddr, addr.source, addr.daddr, addr.dest);
	return hash % tcpStreamTableSize;
}
	
int CTcpState::GetTs(tcphdr *thisTcpHeader, UINT *ts)
{
	int len = 4 * thisTcpHeader->th_off;
	unsigned int tmpTs;
	unsigned char * options = (unsigned char*)(thisTcpHeader + 1);
	int ind = 0, ret = 0;

	while (ind <=  len - (int)sizeof (struct tcphdr) - 10 )
		switch (options[ind]) {
		case 0: /* TCPOPT_EOL */
			return ret;

		case 1: /* TCPOPT_NOP */
			ind++;
			continue;	

		case 8: /* TCPOPT_TIMESTAMP */
			memcpy((char*)&tmpTs, options + ind + 2, 4);
			*ts=ntohl(tmpTs);
			ret = 1;
			/* no break, intentionally */
		default:	
			if (options[ind+1] < 2 ) /* "silly option" */
				return ret;
			ind += options[ind+1];
	}			

	return ret;
}  		


int CTcpState::GetWscale(tcphdr *thisTcpHeader, UINT *ws)
{
	int len = 4 * thisTcpHeader->th_off;
	unsigned int tmp_ws;
	unsigned char * options = (unsigned char*)(thisTcpHeader + 1);
	int ind = 0, ret = 0;
	*ws=1;

	while (ind <=  len - (int)sizeof (struct tcphdr) - 3 )
		switch (options[ind]) {
		case 0: /* TCPOPT_
				EOL */
			return ret;

		case 1: /* TCPOPT_NOP */
			ind++;
			continue;	

		case 3: /* TCPOPT_WSCALE */
			tmp_ws=options[ind+2];
			if (tmp_ws>14) 
				tmp_ws=14;

			*ws=1<<tmp_ws;
			ret = 1;

			/* no break, intentionally */
		default:	
			if (options[ind+1] < 2 ) /* "silly option" */
				return ret;

			ind += options[ind+1];
	}			

	return ret;
}  	



void CTcpState::AddFromSkb(tcp_stream *tcpStream, half_stream *rcvStream, half_stream *sndStream, UCHAR *data, int datalen, UINT thisSeq, char fin, char urg, UINT urgPtr)
{
	u_int lost = ExpSeq(sndStream, rcvStream) - thisSeq;
	int toCopy, toCopy2;

	if (urg && after(urgPtr, ExpSeq(sndStream, rcvStream) - 1) &&
		(!rcvStream->urg_seen || after(urgPtr, rcvStream->urg_ptr))) {
			rcvStream->urg_ptr = urgPtr;
			rcvStream->urg_seen = 1;
	}

	if (rcvStream->urg_seen && after(rcvStream->urg_ptr + 1, thisSeq + lost) && before(rcvStream->urg_ptr, thisSeq + datalen)) {
		toCopy = rcvStream->urg_ptr - (thisSeq + lost);

		if (toCopy > 0) {
			if (rcvStream->collect) {
				add2buf(rcvStream, (char *)(data + lost), toCopy);
				NotifyListeners(tcpStream, rcvStream);
			}
			else {
				rcvStream->count += toCopy;
				rcvStream->offset = rcvStream->count; /* clear the buffer */
			}
		}

		rcvStream->urgdata = data[rcvStream->urg_ptr - thisSeq];
		rcvStream->count_new_urg = 1;
		NotifyListeners(tcpStream, rcvStream);

		rcvStream->count_new_urg = 0;
		rcvStream->urg_seen = 0;
		rcvStream->urg_count++;
		toCopy2 = thisSeq + datalen - rcvStream->urg_ptr - 1;

		if (toCopy2 > 0) {
			if (rcvStream->collect) {
				add2buf(rcvStream, (char *)(data + lost + toCopy + 1), toCopy2);
				NotifyListeners(tcpStream, rcvStream);
			}
			else {
				rcvStream->count += toCopy2;
				rcvStream->offset = rcvStream->count; /* clear the buffer */
			}
		}
	}
	else {
		if (datalen - lost > 0) {
			if (rcvStream->collect) {
				add2buf(rcvStream, (char *)(data + lost), datalen - lost);
				NotifyListeners(tcpStream, rcvStream);
			}
			else {
				rcvStream->count += datalen - lost;
				rcvStream->offset = rcvStream->count; /* clear the buffer */
			}
		}
	}

	if (fin) {
		sndStream->state = FIN_SENT;
		if (rcvStream->state == TCP_CLOSING)
			AddTcpClosingTimeout(tcpStream);
	}
}


void CTcpState::AddNewTcp(tcphdr *thisTcpHeader, ip *thisIpHeader)
{
	struct tcp_stream *tolink;
	struct tcp_stream *tcpStream;
	int hashIndex;
	struct tuple4 addr;

	addr.source = ntohs(thisTcpHeader->th_sport);
	addr.dest   = ntohs(thisTcpHeader->th_dport);
	addr.saddr  = thisIpHeader->ip_src.s_addr;
	addr.daddr  = thisIpHeader->ip_dst.s_addr;
	hashIndex  = MakeHashIndex(addr);

	if (tcpNum > maxStream) {
		struct lurker_node *i;
		int orig_client_state = tcpOldest->client.state;
		tcpOldest->nids_state = NIDS_TIMED_OUT;

		for (i = tcpOldest->listeners; i; i = i->next)
			((void (__cdecl*)(tcp_stream*, void**, void *))i->item) (tcpOldest, &i->data, i->userParam);

		FreeStream(tcpOldest);

		if (orig_client_state != TCP_SYN_SENT)
			((int (__cdecl*)(int,int,ip*,void*))nidsParams->syslog)(NIDS_WARN_TCP, NIDS_WARN_TCP_TOOMUCH, uglyIpHeader, thisTcpHeader);
	}
	tcpStream = freeStreams;

	assert(tcpStream != NULL);

	freeStreams = tcpStream->next_free;

	tcpNum++;
	tolink = tcpStreamTable[hashIndex];

	memset(tcpStream, 0, sizeof(struct tcp_stream));
	tcpStream->hash_index = hashIndex;
	tcpStream->addr = addr;
	tcpStream->client.state = TCP_SYN_SENT;
	tcpStream->client.seq = ntohl(thisTcpHeader->th_seq) + 1;
	tcpStream->client.first_data_seq = tcpStream->client.seq;
	tcpStream->client.window = ntohs(thisTcpHeader->th_win);
	tcpStream->client.ts_on = (u_char)GetTs(thisTcpHeader, &tcpStream->client.curr_ts);
	tcpStream->client.wscale_on = (u_char)GetWscale(thisTcpHeader, &tcpStream->client.wscale);
	tcpStream->server.state = TCP_CLOSE;
	tcpStream->next_node = tolink;
	tcpStream->prev_node = 0;

	if (tolink)
		tolink->prev_node = tcpStream;

	tcpStreamTable[hashIndex] = tcpStream;
	tcpStream->next_time = tcpLatest;
	tcpStream->prev_time = 0;

	if (!tcpOldest)
		tcpOldest = tcpStream;

	if (tcpLatest)
		tcpLatest->prev_time = tcpStream;

	tcpLatest = tcpStream;
}


void CTcpState::add2buf(half_stream *rcvStream, char *data, int datalen)
{
	int toalloc;

	if (datalen + rcvStream->count - rcvStream->offset > rcvStream->bufsize) {
		if (!rcvStream->data) {
			if (datalen < 2048)
				toalloc = 4096;
			else
				toalloc = datalen * 2;
			rcvStream->data = (char*)malloc(toalloc);
			rcvStream->bufsize = toalloc;
		}
		else {
			if (datalen < rcvStream->bufsize)
				toalloc = 2 * rcvStream->bufsize;
			else	
				toalloc = rcvStream->bufsize + 2*datalen;

			char* swapBuffer = (char*)malloc(toalloc);
			if (swapBuffer == NULL) {
				// Uh oh...
				assert(false);
				return;
			}
			memcpy_s(swapBuffer, toalloc, rcvStream->data, rcvStream->bufsize);
			free(rcvStream->data);
			rcvStream->data = swapBuffer;
			
			rcvStream->bufsize = toalloc;
		}
		if (!rcvStream->data)
			nidsParams->no_mem("add2buf");
	}

	memcpy_s(rcvStream->data + rcvStream->count - rcvStream->offset, rcvStream->bufsize, data, datalen);
	rcvStream->count_new = datalen;
	rcvStream->count += datalen;
}


	
void CTcpState::RideLurkers(tcp_stream *tcpStream, char mask)
{
	struct lurker_node *i;
	char cc, sc, ccu, scu;

	for (i = tcpStream->listeners; i; i = i->next) {
		if (i->whatto & mask) {
			cc = tcpStream->client.collect;
			sc = tcpStream->server.collect;
			ccu = tcpStream->client.collect_urg;
			scu = tcpStream->server.collect_urg;

			((void (__cdecl*)(tcp_stream*,void**,void*)) i->item) (tcpStream, &i->data, i->userParam);
			if (cc < tcpStream->client.collect)
				i->whatto |= COLLECT_cc;
			if (ccu < tcpStream->client.collect_urg)
				i->whatto |= COLLECT_ccu;
			if (sc < tcpStream->server.collect)
				i->whatto |= COLLECT_sc;
			if (scu < tcpStream->server.collect_urg)
				i->whatto |= COLLECT_scu;
			if (cc > tcpStream->client.collect)
				i->whatto &= ~COLLECT_cc;
			if (ccu > tcpStream->client.collect_urg)
				i->whatto &= ~COLLECT_ccu;
			if (sc > tcpStream->server.collect)
				i->whatto &= ~COLLECT_sc;
			if (scu > tcpStream->server.collect_urg)
				i->whatto &= ~COLLECT_scu;
		}
	}
}


void CTcpState::NotifyListeners(tcp_stream *tcpStream, half_stream *rcv)
{
	struct lurker_node *i, **prevAddr;
	char mask;

	if (rcv->count_new_urg) {
		if (!rcv->collect_urg)
			return;

		if (rcv == &tcpStream->client)
			mask = COLLECT_ccu;
		else
			mask = COLLECT_scu;
		
		RideLurkers(tcpStream, mask);
		goto prune_listeners;
	}

	if (rcv->collect) {
		if (rcv == &tcpStream->client)
			mask = COLLECT_cc;
		else
			mask = COLLECT_sc;

		do {
			int total;
			tcpStream->read = rcv->count - rcv->offset;
			total=tcpStream->read;

			RideLurkers(tcpStream, mask);
			if (tcpStream->read>total-rcv->count_new)
				rcv->count_new=total-tcpStream->read;

			if (tcpStream->read > 0) {
				memmove(rcv->data, rcv->data + tcpStream->read, rcv->count - rcv->offset - tcpStream->read);
				rcv->offset += tcpStream->read;
			}
		} while (nidsParams->one_loop_less && tcpStream->read > 0 && rcv->count_new); 
		
		// we know that if one_loop_less!=0, we have only one callback to notify
		rcv->count_new=0;	    
	}

prune_listeners:
	prevAddr = &tcpStream->listeners;
	i = tcpStream->listeners;
	while (i) {
		if (!i->whatto) {
			*prevAddr = i->next;
			free(i);
			i = *prevAddr;
		}
		else {
			prevAddr = &i->next;
			i = i->next;
		}
	}
}


	
void CTcpState::HandleAck(half_stream *halfStream, UINT acknum)
{
	int ackdiff;

	ackdiff = acknum - halfStream->ack_seq;
	if (ackdiff > 0) {
		halfStream->ack_seq = acknum;
	}
}


tcp_stream * CTcpState::FindStream(tcphdr *thisTcpHeader, ip *thisIpHeader, int *fromClient)
{
	struct tuple4 thisAddr, reversed;
	struct tcp_stream *tcpStream;

	thisAddr.source = ntohs(thisTcpHeader->th_sport);
	thisAddr.dest   = ntohs(thisTcpHeader->th_dport);
	thisAddr.saddr  = thisIpHeader->ip_src.s_addr;
	thisAddr.daddr  = thisIpHeader->ip_dst.s_addr;
	tcpStream       = FindStream(&thisAddr);

	if (tcpStream) {
		*fromClient = 1;
		return tcpStream;
	}

	reversed.source = ntohs(thisTcpHeader->th_dport);
	reversed.dest   = ntohs(thisTcpHeader->th_sport);
	reversed.saddr  = thisIpHeader->ip_dst.s_addr;
	reversed.daddr  = thisIpHeader->ip_src.s_addr;
	tcpStream       = FindStream(&reversed);

	if (tcpStream) {
		*fromClient = 0;
		return tcpStream;
	}

	return 0;
}


tcp_stream * CTcpState::FindStream(tuple4 *addr)
{
	int hashIndex;
	struct tcp_stream *tcpStream;

	hashIndex = MakeHashIndex(*addr);
	for (tcpStream = tcpStreamTable[hashIndex]; tcpStream && memcmp(&tcpStream->addr, addr, sizeof (struct tuple4)); tcpStream = tcpStream->next_node);

	return tcpStream;
}


void CTcpState::FreeStream(tcp_stream *tcpStream)
{
	int hashIndex = tcpStream->hash_index;
	struct lurker_node *i, *j;

	DelTcpClosingTimeout(tcpStream);
	PurgeQueue(&tcpStream->server);
	PurgeQueue(&tcpStream->client);

	if (tcpStream->next_node)
		tcpStream->next_node->prev_node = tcpStream->prev_node;

	if (tcpStream->prev_node)
		tcpStream->prev_node->next_node = tcpStream->next_node;
	else
		tcpStreamTable[hashIndex] = tcpStream->next_node;

	if (tcpStream->client.data)
		free(tcpStream->client.data);

	if (tcpStream->server.data)
		free(tcpStream->server.data);

	if (tcpStream->next_time)
		tcpStream->next_time->prev_time = tcpStream->prev_time;

	if (tcpStream->prev_time)
		tcpStream->prev_time->next_time = tcpStream->next_time;

	if (tcpStream == tcpOldest)
		tcpOldest = tcpStream->prev_time;

	if (tcpStream == tcpLatest)
		tcpLatest = tcpStream->next_time;

	i = tcpStream->listeners;

	while (i) {
		j = i->next;
		free(i);
		i = j;
	}

	tcpStream->next_free = freeStreams;
	freeStreams = tcpStream;
	tcpNum--;
}



void CTcpState::Discard(tcp_stream *tcpStream, int num)
{
	if (num < tcpStream->read)
		tcpStream->read = num;
}


void CTcpState::RegisterTcp(void (*x), void *data)
{
	register_callback(&tcpProcs, x, data);
}


void CTcpState::UnregisterTcp(void (*x), void *data)
{
	unregister_callback(&tcpProcs, x, data);
}



#ifdef ENABLE_TCPREASM
tcp_stream * CTcpState::InitiateTcpResume(tcphdr *thisTcpHeader, ip *thisIpHeader, int direction)
{
	tcp_stream *tolink, *tcpStream;
	half_stream *half, *otherHalf;
	int hashIndex;
	tuple4 addr;
	
	switch (direction)
	{
	case NIDS_TCP_RESUME_CLIENT:
		addr.source = ntohs(thisTcpHeader->th_sport);
		addr.dest   = ntohs(thisTcpHeader->th_dport);
		addr.saddr  = thisIpHeader->ip_src.s_addr;
		addr.daddr  = thisIpHeader->ip_dst.s_addr;
		break;

	case NIDS_TCP_RESUME_SERVER:
		addr.source = ntohs(thisTcpHeader->th_dport);
		addr.dest   = ntohs(thisTcpHeader->th_sport);
		addr.saddr  = thisIpHeader->ip_dst.s_addr;
		addr.daddr  = thisIpHeader->ip_src.s_addr;
		break;
	
	default:
		return NULL;
	}
	hashIndex = MakeHashIndex(addr);

	if (tcpNum > maxStream) {
		struct lurker_node *i;

		tcpOldest->nids_state = NIDS_TIMED_OUT;
		for (i = tcpOldest->listeners; i; i = i->next)
			((void (__cdecl*)(tcp_stream*, void**, void *))i->item)(tcpOldest, &i->data, i->userParam);
		
		FreeStream(tcpOldest);
		((int (__cdecl*)(int,int,ip*,void*))nidsParams->syslog)(NIDS_WARN_TCP, NIDS_WARN_TCP_TOOMUCH, uglyIpHeader, thisTcpHeader);
	}

	tcpStream = freeStreams;

	assert(tcpStream != NULL);

	freeStreams = tcpStream->next_free;

	tcpNum++;
	tolink = tcpStreamTable[hashIndex];
	memset(tcpStream, 0, sizeof(struct tcp_stream));
	tcpStream->hash_index = hashIndex;
	tcpStream->addr = addr;

	if (direction == NIDS_TCP_RESUME_CLIENT) {
		half = &tcpStream->client;
		otherHalf = &tcpStream->server;
	} else {
		half = &tcpStream->server;
		otherHalf = &tcpStream->client;
	}

	half->state = TCP_ESTABLISHED;
	half->seq = ntohl(thisTcpHeader->th_seq) + 1;
	half->first_data_seq = half->seq - 1;
	half->window = ntohs(thisTcpHeader->th_win);
	half->ts_on = 0;
	half->wscale = nidsParams->tcp_resume_wscale;

	if (thisTcpHeader->th_flags & TH_ACK)
		half->ack_seq = ntohl(thisTcpHeader->th_ack);

#ifdef ENABLE_TCPREASM_DEBUG
	DEBUG_REASSEMBLY("new connection: seq = %u, ack_seq = %u\n", 
		half->seq, half->ack_seq);
#endif

	otherHalf->ack_seq = half->seq;
	otherHalf->state = TCP_ESTABLISHED;
	otherHalf->resume_second_half = 1;
	otherHalf->ts_on = 0;
	otherHalf->window = half->window;
	otherHalf->wscale = nidsParams->tcp_resume_wscale;

	tcpStream->next_node = tolink;
	tcpStream->prev_node = 0;
	
	if (tolink)
		tolink->prev_node = tcpStream;
	
	tcpStreamTable[hashIndex] = tcpStream;
	tcpStream->next_time = tcpLatest;
	tcpStream->prev_time = 0;
	
	if (!tcpOldest)
		tcpOldest = tcpStream;
	
	if (tcpLatest)
		tcpLatest->prev_time = tcpStream;
	
	tcpLatest = tcpStream;

	return tcpStream;
}


void CTcpState::NidsRegisterTcpResume(void (*x), void *data)
{
	register_callback(&tcpResumeProcs, x, data);
}


void CTcpState::NidsUnregisterTcpResume(void (*x), void *data)
{
	unregister_callback(&tcpResumeProcs, x, data);
}

int CTcpState::IsWhitelisted(unsigned int ip)
{
	int i;
	for (i = 0; i < whitelistSize; i++)
		if ((ip & checksumWhitelist[i].mask) == checksumWhitelist[i].netaddr)
			return checksumWhitelist[i].action;

	return 0;
}

u_short CTcpState::Checksum(struct tcphdr *th, int len, u_int saddr, u_int daddr) {
	unsigned int i;
	int sum = 0;
	psuedo_hdr hdr;

	if (IsWhitelisted(saddr))
		return 0;

	hdr.saddr = saddr;
	hdr.daddr = daddr;
	hdr.zero = 0;
	hdr.protocol = IPPROTO_TCP;
	hdr.len = htons((u_short)len);
	for (i = 0; i < sizeof(hdr); i += 2)
		sum += *(u_short *)((char *)(&hdr) + i);

	return (ip_check_ext((u_short *)th, len, sum));
} 
#endif
