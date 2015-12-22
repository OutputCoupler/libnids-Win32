
#include "config.h"
#include "LibnidsState.h"
#include "checksum.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "ip_fragment.h"
#include "util.h"

extern int ip_options_compile(unsigned char *);

// Do nothing syslog if the user doesn't provide one
// TODO: Improve this
void NidsSyslog(int, int, struct ip, void*){}

// Do nothing IP Filter
int NidsIpFilter(ip*, int) { return 1; }

CLibnidsState::CLibnidsState(nids_prm params)
{
	nidsParams = params;

	memset(errBuf, 0, sizeof(errBuf));

	scanner = new CScanner(&params);
	tcpState = new CTcpState(&params, scanner);

	tcpTimeouts = NULL;

	ipFragProcs = NULL;
	ipProcs = NULL;
	udpProcs = NULL;
	tcpProcs = NULL;
	tcpResumeProcs = NULL;

	lastPcapHeader = NULL;
	lastPcapData = NULL;
	linkOffset = 0;

	linktype = DLT_EN10MB;

	desc = NULL;
}


CLibnidsState::CLibnidsState(void)
{
	nidsParams.n_tcp_streams   = 1040;
	nidsParams.n_hosts         = 256;
	nidsParams.device          = NULL;
	nidsParams.filename        = NULL;
	nidsParams.sk_buff_size    = 168;
	nidsParams.dev_addon       = -1;
	nidsParams.syslog          = (void (__cdecl*)())NidsSyslog;
	nidsParams.syslog_level    = LOG_ALERT;
	nidsParams.scan_num_hosts  = 256;
	nidsParams.scan_delay      = 3000;
	nidsParams.scan_num_ports  = 10;
	nidsParams.no_mem          = nids_no_mem;
	nidsParams.ip_filter       = (int (__cdecl*)())NidsIpFilter;
	nidsParams.pcap_filter     = NULL;
	nidsParams.promisc         = 1;
	nidsParams.one_loop_less   = 0;
	nidsParams.pcap_timeout    = 1024;
	nidsParams.multiproc       = 0;
	nidsParams.queue_limit     = 20000;
	nidsParams.tcp_workarounds = 0;
	nidsParams.pcap_desc       = NULL;
#ifdef ENABLE_TCPREASM
	nidsParams.tcp_resume_wscale = 1;
#endif;

	memset(errBuf, 0, sizeof(errBuf));

	scanner = new CScanner(&nidsParams);
	tcpState = new CTcpState(&nidsParams, scanner);

	tcpTimeouts = NULL;

	ipFragProcs = NULL;
	ipProcs = NULL;
	udpProcs = NULL;
	tcpProcs = NULL;
	tcpResumeProcs = NULL;

	lastPcapHeader = NULL;
	lastPcapData = NULL;
	linkOffset = 0;

	linktype = DLT_EN10MB;

	desc = NULL;

}


CLibnidsState::~CLibnidsState(void)
{
	if (tcpState != NULL)
		delete tcpState;
	if (scanner != NULL)
		delete scanner;
}


// This just casts the user pointer to a pointer to the correct state object,
// then invokes its callback to handle the data. Just a simple workaround for
// using member function pointers instead of a normal function pointer.
// This method is only used for live PCAP capture.
void pcapHandlerPassthrough(u_char *user, pcap_pkthdr *header, u_char *data)
{
	if (user == NULL)
		return;

	CLibnidsState* state = (CLibnidsState*)(user);
	state->PcapHandler(NULL, header, data, NULL);
}

/* called either directly from pcap_hand() or from cap_queue_process_thread()
* depending on the value of nidsParams.multiproc - mcree
*/
void CLibnidsState::CallIpFragProcs(void *data, bpf_u_int32 caplen, u_int * flags)
{
	GenIpFragProc((u_char*)data, caplen, flags);
	struct proc_node *i;
	for (i = ipFragProcs; i; i = i->next)
		((void(__cdecl*)(void*, bpf_u_int32, u_int*))(i->item))(data, caplen, flags);
}


void CLibnidsState::PcapHandler(u_char * par, struct pcap_pkthdr *hdr, u_char * data, u_int * flags)
{
	UNREFERENCED_PARAMETER(par);

	// Zeroize the flags, if provided (will be absent from live PCAP captures)
	if (flags)
		*flags = 0;

	u_char *data_aligned;

#ifdef HAVE_LIBGTHREAD_2_0
	struct cap_queue_item *qitem;
#endif

#ifdef DLT_IEEE802_11
	unsigned short fc;
	int linkoffset_tweaked_by_prism_code = 0;
	int linkoffset_tweaked_by_radio_code = 0;
#endif

	/*
	* Check for savagely closed TCP connections. Might
	* happen only when nidsParams.tcp_workarounds is non-zero;
	* otherwise tcpTimeouts is always NULL.
	*/
	tcpState->CheckTcpTimeouts(&hdr->ts);

	lastPcapHeader = hdr;
	lastPcapData = data;
	
	switch (linktype) {
	case DLT_EN10MB:
		if (hdr->caplen < 14)
			return;
		/* Only handle IP packets and 802.1Q VLAN tagged packets below. */
		if (data[12] == 8 && data[13] == 0) {
			/* Regular ethernet */
			linkOffset = 14;
		} else if (data[12] == 0x81 && data[13] == 0) {
			/* Skip 802.1Q VLAN and priority information */
			linkOffset = 18;
		} else
			/* non-ip frame */
			return;
		break;
#ifdef DLT_PRISM_HEADER
#ifndef DLT_IEEE802_11
#error DLT_PRISM_HEADER is defined, but DLT_IEEE802_11 is not ???
#endif
	case DLT_PRISM_HEADER:
		linkOffset = 144; //sizeof(prism2_hdr);
		linkoffset_tweaked_by_prism_code = 1;
		//now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11_RADIO
	case DLT_IEEE802_11_RADIO:
		// just get rid of the radio tap header
		if (!linkoffset_tweaked_by_prism_code) {
			linkOffset = EXTRACT_LE_16BITS(data + 2); // skip radiotap header
			linkoffset_tweaked_by_radio_code = 1;
		}
		//now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11
	case DLT_IEEE802_11:
		/* I don't know why frame control is always little endian, but it 
		* works for tcpdump, so who am I to complain? (wam)
		*/
		if (!linkoffset_tweaked_by_prism_code && !linkoffset_tweaked_by_radio_code)
			linkOffset = 0;

		fc = EXTRACT_LE_16BITS(data + linkOffset);
		if (FC_TYPE(fc) != T_DATA || FC_WEP(fc)) {
			return;
		}

		if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
			/* a wireless distribution system packet will have another
			* MAC addr in the frame
			*/
			linkOffset += 30;
		} else {
			linkOffset += 24;
		}

		if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
			linkOffset += 2;
		
		if (hdr->len < linkOffset + LLC_FRAME_SIZE)
			return;
		
		if (ETHERTYPE_IP != EXTRACT_16BITS(data + linkOffset + LLC_OFFSET_TO_TYPE_FIELD)) {
				/* EAP, LEAP, and other 802.11 enhancements can be 
				* encapsulated within a data packet too.  Look only at
				* encapsulated IP packets (Type field of the LLC frame).
				*/
				return;
		}
		linkOffset += LLC_FRAME_SIZE;
		break;
#endif
	default:;
	}

	if (hdr->caplen < linkOffset)
		return;

	/*
	* sure, memcpy costs. But many EXTRACT_{SHORT, LONG} macros cost, too. 
	* Anyway, libpcap tries to ensure proper layer 3 alignment (look for
	* handle->offset in pcap sources), so memcpy should not be called.
	*/
#ifdef LBL_ALIGN
	if ((unsigned long) (data + linkOffset) & 0x3) {
		data_aligned = alloca(hdr->caplen - linkOffset + 4);
		data_aligned -= (unsigned long) data_aligned % 4;
		memcpy(data_aligned, data + linkOffset, hdr->caplen - linkOffset);
	} else 
#endif
		data_aligned = data + linkOffset;

	CallIpFragProcs(data_aligned, hdr->caplen - linkOffset, flags);
}


void CLibnidsState::GenIpFragProc(u_char * data, int len, u_int * flags)
{
	struct proc_node *i;
	struct ip *iph = (struct ip *) data;
	int need_free = 0;
	int skblen;
	
	void (*glibc_syslog_h_workaround)(int, int, struct ip *, void*) = (void (__cdecl*)(int,int,ip*,void*))nidsParams.syslog;

	if (!((int (__cdecl*)(ip*,int))nidsParams.ip_filter)(iph, len))
		return;

	if (len < (int)sizeof(struct ip) || 
		iph->ip_hl < 5 || 
		iph->ip_v != 4 || 
		IpFastChecksum((unsigned short *) iph, iph->ip_hl) != 0 || 
		len < ntohs(iph->ip_len) || 
		ntohs(iph->ip_len) < iph->ip_hl << 2) 
	{
		glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_HDR, iph, 0);
		return;
	}

	if (iph->ip_hl > 5 && ip_options_compile((unsigned char *)data)) {
		glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_SRR, iph, 0);
		return;
	}

	switch (m_ipFragmentHandler.ip_defrag_stub((struct ip *) data, &iph, flags, &nidsParams)) {
	case IPF_ISF:
		return;

	case IPF_NOTF:
		need_free = 0;
		iph = (struct ip *) data;
		break;
	
	case IPF_NEW:
		need_free = 1;
		break;
	
	default:;
	}

	skblen = ntohs(iph->ip_len) + 16;
	if (!need_free)
		skblen += nidsParams.dev_addon;

	skblen = (skblen + 15) & ~15;
	skblen += nidsParams.sk_buff_size;

	GenIpProc((u_char*)iph, skblen, flags);
	for (i = ipProcs; i; i = i->next)
		((void(__cdecl*)(ip*, int, u_int*))(i->item)) (iph, skblen, flags);

	if (need_free)
		free(iph);
}


// TODO: Do stuff with flags -wdm
void CLibnidsState::ProcessUdp(char *data, u_int * flags)
{
	proc_node *ipp = udpProcs;
	ip *iph = (ip *) data;
	udphdr *udph;
	tuple4 addr;

	int hlen = iph->ip_hl << 2;
	int len = ntohs(iph->ip_len);
	int ulen;
	if (len - hlen < (int)sizeof(udphdr))
		return;

	udph = (udphdr *) (data + hlen);
	ulen = ntohs(udph->UH_ULEN);
	if (len - hlen < ulen || ulen < (int)sizeof(udphdr))
		return;

	/* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */
	u_short intermediateChksumVal = 0;
	if (udph->uh_sum && UdpChecksum((void *) udph, ulen, iph->ip_src.s_addr, iph->ip_dst.s_addr, &intermediateChksumVal)) {
		if (intermediateChksumVal == udph->uh_sum) {
			*flags |= NIDS_CHKSUM_OFFLOAD_DETECTED;
		} else {
			*flags |= NIDS_CHKSUM_FAIL;
			return;
		}
	}

	addr.source = ntohs(udph->UH_SPORT);
	addr.dest = ntohs(udph->UH_DPORT);
	addr.saddr = iph->ip_src.s_addr;
	addr.daddr = iph->ip_dst.s_addr;


	while (ipp) {
		((void (__cdecl*)(tuple4*,char*,int,char*,void*))ipp->item)(&addr, ((char *) udph) + sizeof(udphdr), ulen - sizeof(udphdr), data, ipp->userParam);
		ipp = ipp->next;
	}
}


void CLibnidsState::GenIpProc(u_char * data, int skblen, u_int * flags)
{
	switch (((struct ip *) data)->ip_p) {
	case IPPROTO_TCP:
		tcpState->ProcessTcp(data, skblen, flags);
		break;

	case IPPROTO_UDP:
		ProcessUdp((char *)data, flags);
		break;

	case IPPROTO_ICMP:
		if (nidsParams.n_tcp_streams)
			tcpState->ProcessIcmp(data, flags);
		break;

	default:
		break;
	}
}

void CLibnidsState::InitProcs()
{
	ipFragProcs = NULL;
	ipProcs = NULL;
	tcpProcs = NULL;
	udpProcs = NULL;

#ifdef ENABLE_TCPREASM
	tcpResumeProcs = NULL;
#endif
}

void CLibnidsState::RegisterUdp(void (*x), void *info)
{
	register_callback(&udpProcs, x, info);
}

void CLibnidsState::UnregisterUdp(void (*x), void *info)
{
	unregister_callback(&udpProcs, x, info);
}

void CLibnidsState::RegisterIp(void (*x), void *info)
{
	register_callback(&ipProcs, x, info);
}

void CLibnidsState::UnregisterIp(void (*x), void *info)
{
	unregister_callback(&ipProcs, x, info);
}

void CLibnidsState::RegisterIpFrag(void (*x), void *info)
{
	register_callback(&ipFragProcs, x, info);
}

void CLibnidsState::UnregisterIpFrag(void (*x), void *info)
{
	unregister_callback(&ipFragProcs, x, info);
}

int CLibnidsState::OpenLive()
{
	char *device;
	int promisc = 0;

	if (nidsParams.device == NULL)
		nidsParams.device = pcap_lookupdev(errBuf);
	if (nidsParams.device == NULL)
		return 0;

	device = nidsParams.device;
	if (!strcmp(device, "all"))
		device = "any";
	else
		promisc = (nidsParams.promisc != 0);

	if ((desc = pcap_open_live(device, 16384, promisc, nidsParams.pcap_timeout, errBuf)) == NULL)
		return 0;

	if (!raw_init()) {
		errBuf[0] = 0;
		char strerrbuf[256];
		if (strerror_s(strerrbuf, sizeof(strerrbuf), errno) == 0) {
			strncat_s(errBuf, sizeof(errBuf), strerrbuf, sizeof(errBuf) - 1);	// Don't really care if this fails, not checking return
		}
		return 0;
	}
	return 1;
}


int CLibnidsState::Init(bool standaloneMode /*= false*/)
{
	/* free resources that previous usages might have allocated */
	Exit();

	if (standaloneMode == false) {
		if (nidsParams.pcap_desc) {
			desc = nidsParams.pcap_desc;
		} else if (nidsParams.filename) {
			if ((desc = pcap_open_offline(nidsParams.filename, errBuf)) == NULL)
				return 0;
		} else if (!OpenLive()) {
			return 0;
		}
		
		if (nidsParams.pcap_filter != NULL) {
			u_int mask = 0;
			struct bpf_program fcode;

			if (pcap_compile(desc, &fcode, nidsParams.pcap_filter, 1, mask) < 0) 
				return 0;
			if (pcap_setfilter(desc, &fcode) == -1)
				return 0;
		}
		
		linktype = pcap_datalink(desc);
	}

	switch (linktype) {
#ifdef DLT_IEEE802_11
#ifdef DLT_PRISM_HEADER
	case DLT_PRISM_HEADER:
#endif
#ifdef DLT_IEEE802_11_RADIO
	case DLT_IEEE802_11_RADIO:
#endif
	case DLT_IEEE802_11:
		/* wireless, need to calculate offset per frame */
		break;
#endif
#ifdef DLT_NULL
	case DLT_NULL:
		linkOffset = 4;
		break;
#endif        
	case DLT_EN10MB:
		linkOffset = 14;
		break;
	case DLT_PPP:
		linkOffset = 4;
		break;
		/* Token Ring Support by vacuum@technotronic.com, thanks dugsong! */
	case DLT_IEEE802:
		linkOffset = 22;
		break;

	case DLT_RAW:
	case DLT_SLIP:
		linkOffset = 0;
		break;
#define DLT_LINUX_SLL   113
	case DLT_LINUX_SLL:
		linkOffset = 16;
		break;
#ifdef DLT_FDDI
	case DLT_FDDI:
		linkOffset = 21;
		break;
#endif        
#ifdef DLT_PPP_SERIAL 
	case DLT_PPP_SERIAL:
		linkOffset = 4;
		break;
#endif        
	default:
#ifdef WIN32
		strcpy_s(errBuf, sizeof(errBuf), "link type unknown");	// Don't care if this fails, not checking the return value
#else
		strcpy(errBuf, "link type unknown");
#endif
		return 0;
	}
	if (nidsParams.dev_addon == -1) {
		if (linktype == DLT_EN10MB)
			nidsParams.dev_addon = 16;
		else
			nidsParams.dev_addon = 0;
	}
#ifndef WIN32
	if (nidsParams.syslog == nids_syslog)
		openlog("libnids", 0, LOG_LOCAL0);
#endif

	InitProcs();
	m_ipFragmentHandler.ip_frag_init(nidsParams.n_hosts, &nidsParams);

	if(nidsParams.multiproc) {
#ifdef HAVE_LIBGTHREAD_2_0
		g_thread_init(NULL);
		cap_queue=g_async_queue_new();
#else
#ifdef WIN32
		strcpy_s(errBuf, sizeof(errBuf), "libnids was compiled without threads support");	// Don't care if this fails, not checking the return value
#else
		strcpy(errBuf, "libnids was compiled without threads support");
#endif
		return 0;        
#endif
	}

	return 1;
}

int CLibnidsState::Run()
{
	if (!desc) {
		strcpy_s(errBuf, sizeof(errBuf), "Libnids not initialized");	// Don't care if this fails, not checking the return value
		return 0;
	}

	START_CAP_QUEUE_PROCESS_THREAD(); /* threading... */
	pcap_loop(desc, -1, (pcap_handler)pcapHandlerPassthrough, (u_char*)this);

	/* FIXME: will this code ever be called? Don't think so - mcree */
	STOP_CAP_QUEUE_PROCESS_THREAD(); 
	Exit();
	return 0;
}

void CLibnidsState::Exit()
{
	if (!desc) {
		strcpy_s(errBuf, sizeof(errBuf), "Libnids not initialized");	// Don't care if this fails, not checking the return value
		return;
	}

#ifdef HAVE_LIBGTHREAD_2_0
	if (nidsParams.multiproc) {
		/* I have no portable sys_sched_yield,
		and I don't want to add more synchronization...
		*/
		while (g_async_queue_length(cap_queue)>0) 
			usleep(100000);
	}
#endif

	tcpState->Exit();
	m_ipFragmentHandler.ip_frag_exit();
	scanner->Exit();

	strcpy_s(errBuf, sizeof(errBuf), "loop: ");	// Don't care if this fails, not checking the return value
	strncat_s(errBuf, sizeof(errBuf), pcap_geterr(desc), sizeof errBuf - 7);	// Don't care if this fails, not checking the return value
	
	if (!nidsParams.pcap_desc)
		pcap_close(desc);
	desc = NULL;

	if (ipProcs != NULL) {
		free(ipProcs);
		ipProcs = NULL;
	}

	if (ipFragProcs != NULL) {
		free(ipFragProcs);
		ipFragProcs = NULL;
	}
}

int CLibnidsState::GetFd()
{
	if (!desc) {
		strcpy_s(errBuf, sizeof(errBuf), "Libnids not initialized");	// Don't care if this fails, not checking the return value
		return -1;
	}

	return pcap_fileno(desc);
}

int CLibnidsState::Next()
{
	struct pcap_pkthdr h;
	char *data;

	if (!desc) {
		strcpy_s(errBuf, sizeof(errBuf), "Libnids not initialized");	// Don't care if this fails, not checking the return value
		return 0;
	}

	data = (char *) pcap_next(desc, &h);
	if (!data) {
		strcpy_s(errBuf, sizeof(errBuf), "next: ");	// Don't care if this fails, not checking the return value
		strncat_s(errBuf, sizeof(errBuf), pcap_geterr(desc), sizeof(errBuf) - 7);	// Don't care if this fails, not checking the return value
		return 0;
	}

	/* threading is quite useless (harmful) in this case - should we do an API change?  */
	START_CAP_QUEUE_PROCESS_THREAD();
	PcapHandler(0, &h, (u_char *)data, 0);
	STOP_CAP_QUEUE_PROCESS_THREAD();
	return 1;
}

int CLibnidsState::Dispatch(int cnt)
{
	int r;

	if (!desc) {
		strcpy_s(errBuf, sizeof(errBuf), "Libnids not initialized");	// Don't care if this fails, not checking the return value
		return -1;
	}

	START_CAP_QUEUE_PROCESS_THREAD(); /* threading... */
	r = pcap_dispatch(desc, cnt, (pcap_handler) pcapHandlerPassthrough, (u_char*)this);
	if (r == -1) {
		strcpy_s(errBuf, sizeof(errBuf), "dispatch: ");	// Don't care if this fails, not checking the return value
		strncat_s(errBuf, sizeof(errBuf), pcap_geterr(desc), sizeof(errBuf) - 11);	// Don't care if this fails, not checking the return value
	}
	STOP_CAP_QUEUE_PROCESS_THREAD(); 
	return r;
}

void CLibnidsState::RegisterTcp (void (*x), void *info)
{
	tcpState->RegisterTcp(x, info);
}

void CLibnidsState::UnregisterTcp (void (*x), void *info)
{
	tcpState->UnregisterTcp(x, info);
}

#ifdef ENABLE_TCPREASM
void CLibnidsState::RegisterTcpResume (void (*x), void *info)
{
	tcpState->NidsRegisterTcpResume(x, info);
}

void CLibnidsState::UnregisterTcpResume (void (*x), void *info)
{
	tcpState->NidsUnregisterTcpResume(x, info);
}
#endif

u_short CLibnidsState::UdpChecksum(void *u, int len, u_int saddr, u_int daddr, u_short * intermediateValue) {
	if (IsWhitelisted(saddr))
		return 0;

	struct psuedo_hdr hdr;
	hdr.saddr = saddr;
	hdr.daddr = daddr;
	hdr.zero = 0;
	hdr.protocol = IPPROTO_UDP;
	hdr.len = htons((u_short)len);
	
	int sum = 0;
	for (UINT i = 0; i < sizeof(hdr); i += 2)
		sum += *(u_short *)((char *)(&hdr) + i);

	int intermediate = sum;

	while (intermediate > 0xFFFF) {
		intermediate = (intermediate & 0xFFFF) + (intermediate >> 16);
	}

	*intermediateValue = (u_short)intermediate;

	return (ip_check_ext((u_short *)u, len, sum));
}

u_short CLibnidsState::IpFastChecksum(u_short *addr, int len) 
{
	if (IsWhitelisted(((struct ip*)addr)->ip_src.s_addr))
		return 0;

	return ip_check_ext(addr, len << 2, 0); 
}