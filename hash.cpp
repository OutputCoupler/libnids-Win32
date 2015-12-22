#ifdef WIN32
#define _CRT_RAND_S
#include <stdlib.h>

#include <sys/timeb.h>
#include <time.h>
//#include <WinSock.h>
#include <limits.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;

#else
#include <sys/time.h>
#include <stdlib.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>

static u_char xor[12];
static u_char perm[12];

static void getrnd () {
	u_int *ptr;

#ifndef WIN32
	struct timeval s;
	
	int fd = open ("/dev/urandom", O_RDONLY);
	if (fd > 0)
	{
		read (fd, xor, 12);
		read (fd, perm, 12);
		close (fd);
		return;
	}

	gettimeofday (&s, 0);

	srand (s.tv_usec);
	ptr = (u_int *) xor;
	*ptr = rand ();
	*(ptr + 1) = rand ();
	*(ptr + 2) = rand ();
	ptr = (u_int *) perm;
	*ptr = rand ();
	*(ptr + 1) = rand ();
	*(ptr + 2) = rand ();
#else
	ptr = (u_int *) xor;
	rand_s(ptr);
	rand_s(ptr + 1);
	rand_s(ptr + 2);
	
	ptr = (u_int *) perm;
	rand_s(ptr);
	rand_s(ptr + 1);
	rand_s(ptr + 2);
#endif

}

void
	init_hash ()
{
	int i, n, j;
	int p[12];
	getrnd ();
	for (i = 0; i < 12; i++)
		p[i] = i;
	for (i = 0; i < 12; i++)
	{
		n = perm[i] % (12 - i);
		perm[i] = (u_char)p[n];
		for (j = 0; j < 11 - n; j++)
			p[n + j] = p[n + j + 1];
	}
}

u_int
	mkhash (u_int src, u_short sport, u_int dest, u_short dport)
{
	u_int res = 0;
	int i;
	u_char data[12];
	u_int *stupid_strict_aliasing_warnings=(u_int*)data;
	*stupid_strict_aliasing_warnings = src;
	*(u_int *) (data + 4) = dest;
	*(u_short *) (data + 8) = sport;
	*(u_short *) (data + 10) = dport;
	for (i = 0; i < 12; i++)
		res = ( (res << 8) + (data[perm[i]] ^ xor[i])) % 0xff100f;
	return res;
}
