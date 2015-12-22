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

struct scan {
	unsigned int addr;
	unsigned short port;
	unsigned char flags;
};

struct host {
	struct host *next;
	struct host *prev;
	unsigned int addr;
	int modtime;
	int n_packets;
	struct scan *packets;
};

class CScanner
{
public:
	CScanner(void){}
	CScanner(nids_prm *params);
	~CScanner(void);

	void Exit(void);
	void DetectScan(struct ip *);
	int GetTime();

	static int ScanHash(int addr, int scanNumHosts) { return ((addr % 65536) ^ (addr >> 16)) % (scanNumHosts); }


private:
	nids_prm *nidsParams;
	int timeNow;
	int timeZero;
	host **hashHost;
};

