typedef unsigned short u_short;
typedef unsigned char u_char;

u_short ip_check_ext(register u_short *addr, register int len, int addon)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = addon;
	u_short answer = 0;

	/*
	*  Our algorithm is simple, using a 32 bit accumulator (sum),
	*  we add sequential 16 bit words to it, and at the end, fold
	*  back all the carry bits from the top 16 bits into the lower
	*  16 bits.
	*/
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}  

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */
	answer = (u_short)(~sum);                          /* truncate to 16 bits */
	return (answer);
}

u_short ip_compute_csum(u_short *addr, int len) {
	return ip_check_ext(addr, len, 0);
}