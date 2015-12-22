#pragma once
#include "config.h"
#include "nids.h"
#include "util.h"
#include "scanner.h"
#include "TcpState.h"
#include "ip_fragment.h"

#define TCP_STATE_ERR_BUF_LEN 1024

int NidsIpFilter(struct ip *x, int len);
void NidsSyslog(int, int, struct ip, void*);

class CLibnidsState
{
public:
	CLibnidsState(void);
	CLibnidsState(nids_prm);
	~CLibnidsState(void);

	// You must call this function after constructing your CLibnidsState object to ready it for capture
	int Init(bool standaloneMode = false);

	void PcapHandler(u_char *, pcap_pkthdr *, u_char *, u_int *);

	void RegisterIpFrag(void (*), void *info = NULL);
	void UnregisterIpFrag(void (*), void *info = NULL);

	void RegisterIp(void (*), void *info = NULL);
	void UnregisterIp(void (*), void *info = NULL);

	void RegisterTcp(void (*), void *info = NULL);
	void UnregisterTcp(void (*), void *info = NULL);

#ifdef ENABLE_TCPREASM
	void RegisterTcpResume(void (*), void *info = NULL);
	void UnregisterTcpResume(void (*), void *info = NULL);
#endif

	void RegisterUdp(void (*), void *info = NULL);
	void UnregisterUdp(void (*), void *info = NULL);

	void SetChecksumWhitelist(nids_chksum_ctl *whitelist, int size) { tcpState->SetChecksumWhitelist(whitelist, size); }

	void AddTcpClosingTimeout(tcp_stream *stream) { tcpState->AddTcpClosingTimeout(stream); }
	void DelTcpClosingTimeout(tcp_stream *stream) { tcpState->DelTcpClosingTimeout(stream); }

	void KillTcp(tcp_stream *);
	void Discard(tcp_stream *, int);

	int Run(void);
	void Exit(void);
	int Next(void);

	int GetFd(void);

	int Dispatch(int);

	int OpenLive(void);


private:

	int IsWhitelisted(unsigned int ip) { return tcpState->IsWhitelisted(ip); }
	u_short IpFastChecksum(u_short *addr, int len);

	u_short TcpChecksum(struct tcphdr *th, int len, u_int saddr, u_int daddr) { return tcpState->Checksum(th, len, saddr, daddr); }                     

	u_short UdpChecksum(void *u, int len, u_int saddr, u_int daddr, u_short * intermediateValue);

	void InitProcs(void);

	void CallIpFragProcs(void *data, bpf_u_int32 caplen, u_int * flags);
	void GenIpFragProc(u_char * data, int len, u_int * flags);
	void GenIpProc(u_char * data, int skblen, u_int * flags);

	void ProcessUdp(char *data, u_int * flags);

	char errBuf[PCAP_ERRBUF_SIZE];

	CTcpState *tcpState;
	CScanner *scanner;

	tcp_stream *FindTcpStream(tuple4 *addr) { return tcpState->FindStream(addr); }
	void FreeTcpStream(tcp_stream *);

	tcp_timeout *tcpTimeouts;

	proc_node *ipFragProcs;
	proc_node *ipProcs;
	proc_node *udpProcs;
	proc_node *tcpProcs;
	proc_node *tcpResumeProcs;

	pcap_pkthdr * lastPcapHeader;
	u_char *lastPcapData;
	u_int linkOffset;

	nids_prm nidsParams;

	int linktype;

	pcap_t *desc;

	CIP_FragmentHandler m_ipFragmentHandler;

};