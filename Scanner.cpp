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

#include "Scanner.h"
#include "NETINET\TCP.H"
#include "NETINET\IP.H"
#include <assert.h>

CScanner::CScanner(nids_prm *params)
{
	// We can't do anything without parameters
	if (params == NULL) {
		assert(false);
		return;
	}

	nidsParams = params;

	if (nidsParams->scan_num_hosts > 0) {
		SYSTEMTIME st;
		GetSystemTime(&st);
		timeZero = st.wSecond;

		hashHost = (host **) calloc(nidsParams->scan_num_hosts, sizeof(struct host *));
		if (!hashHost)
			nidsParams->no_mem("scan_init");
	}
}


CScanner::~CScanner(void)
{
	Exit();
}



void CScanner::Exit(void)
{
	if (hashHost) {
		free(hashHost);
		hashHost = NULL;
	}
}

void CScanner::DetectScan(ip *ipHeader)
{
	int i, hash;
	int mtime = 2147483647;
	tcphdr *tcpHeader;
	host *thisHost, *oldestHost = NULL;

	if (nidsParams->scan_num_hosts <= 0)
		return;

	tcpHeader = (tcphdr*)(((char *) ipHeader) + 4 * ipHeader->ip_hl);
	hash = ScanHash(ipHeader->ip_src.s_addr, nidsParams->scan_num_hosts);
	thisHost = hashHost[hash];
	timeNow = 0;

	for (i = 0; thisHost && thisHost->addr != ipHeader->ip_src.s_addr; i++) {
		if (thisHost->modtime < mtime) {
			mtime = thisHost->modtime;
			oldestHost = thisHost;
		}

		thisHost = thisHost->next;
	}

	if (!thisHost) {
		if (i == 10) {
			thisHost = oldestHost;
		} else {
			thisHost = (struct host *) malloc(sizeof(struct host) + (nidsParams->scan_num_ports + 1) * sizeof(struct scan));
			if (!thisHost)
				nidsParams->no_mem("detect_scan");
			thisHost->packets = (struct scan *) (((char *) thisHost) + sizeof(struct host));

			if (hashHost[hash]) {
				hashHost[hash]->prev = thisHost;
				thisHost->next = hashHost[hash];
			}
			else {
				thisHost->next = 0;
			}

			thisHost->prev = 0;
			hashHost[hash] = thisHost;
		}

		thisHost->addr = ipHeader->ip_src.s_addr;
		thisHost->modtime = GetTime();
		thisHost->n_packets = 0;
	}

	if (thisHost->modtime - GetTime() > nidsParams->scan_delay)
		thisHost->n_packets = 0;
	thisHost->modtime = GetTime();

	for (i = 0; i < thisHost->n_packets; i++)
		if (thisHost->packets[i].addr == ipHeader->ip_dst.s_addr && thisHost->packets[i].port == ntohs(tcpHeader->th_dport))
			return;

	thisHost->packets[thisHost->n_packets].addr = ipHeader->ip_dst.s_addr;
	thisHost->packets[thisHost->n_packets].port = ntohs(tcpHeader->th_dport);
	thisHost->packets[thisHost->n_packets].flags = *((unsigned char *) (tcpHeader) + 13);
	thisHost->n_packets++;
	
	if (thisHost->n_packets > nidsParams->scan_num_ports) {
		((int (__cdecl*)(int,int,ip*,void*))nidsParams->syslog)(NIDS_WARN_SCAN, 0, 0, thisHost);
		thisHost->n_packets = 0;
	}
}

int CScanner::GetTime() {
	if (timeNow)
		return timeNow;

	SYSTEMTIME st;
	GetSystemTime(&st);
	timeNow = (st.wSecond - timeZero) * 1000 + st.wMilliseconds;

	return timeNow;
}
