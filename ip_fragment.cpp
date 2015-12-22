#include <sys/timeb.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <time.h>
#include <assert.h>

#include "config.h"
#include <sys/types.h>
#include "netinet/in.h"
#include "netinet/in_systm.h"
#include "netinet/ip.h"
#include "netinet/tcp.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//#include "checksum.h"
#include "ip_fragment.h"
//#include "tcp.h"
#include "util.h"
#include "nids.h"

#define IP_CE		0x8000	/* Flag: "Congestion" */
#define IP_DF		0x4000	/* Flag: "Don't Fragment" */
#define IP_MF		0x2000	/* Flag: "More Fragments" */
#define IP_OFFSET	0x1FFF	/* "Fragment Offset" part */

#define IP_FRAG_TIME	(30 * 1000)	/* fragment lifetime */

#define UNUSED 314159
#define FREE_READ UNUSED
#define FREE_WRITE UNUSED
#define NETDEBUG(x)

/*
Fragment cache limits. We will commit 256K at one time. Should we
cross that limit we will prune down to 192K. This should cope with
even the most extreme cases without allowing an attacker to
measurably harm machine performance.
*/
#define IPFRAG_HIGH_THRESH		(256*1024)
#define IPFRAG_LOW_THRESH		(192*1024)


#define int_ntoa(x)	inet_ntoa(*((in_addr *)&x))

CIP_FragmentHandler::CIP_FragmentHandler()
{
	fragtable = NULL;
	this_host = NULL;
	numpack = 0;
	hash_size = 0;
	timenow = 0;
	time0 = 0;
	timer_head = NULL;
	timer_tail = NULL;
}

int CIP_FragmentHandler::jiffies()
{
	timeval tv;

	if (timenow)
		return timenow;

	SYSTEMTIME st;
	GetSystemTime(&st);
	tv.tv_usec = st.wMilliseconds * 1000;
	tv.tv_sec = st.wSecond;
	timenow = (tv.tv_sec - time0) * 1000 + tv.tv_usec / 1000;

	return timenow;
}

/* Memory Tracking Functions */
void CIP_FragmentHandler::atomic_sub(int ile, int *co)
{
	*co -= ile;
}

void CIP_FragmentHandler::atomic_add(int ile, int *co)
{
	*co += ile;
}

void CIP_FragmentHandler::kfree_skb(sk_buff * skb)
{
	free(skb);
}

void CIP_FragmentHandler::panic(char *str)
{
	fprintf(stderr, "%s", str);
	exit(1);
}

void CIP_FragmentHandler::add_timer(timer_list * x)
{
	if (timer_tail) {
		timer_tail->next = x;
		x->prev = timer_tail;
		x->next = 0;
		timer_tail = x;
	}
	else {
		x->prev = 0;
		x->next = 0;
		timer_tail = timer_head = x;
	}
}

void CIP_FragmentHandler::del_timer(timer_list * x)
{
	if (x->prev)
		x->prev->next = x->next;
	else
		timer_head = x->next;
	if (x->next)
		x->next->prev = x->prev;
	else
		timer_tail = x->prev;
}

void CIP_FragmentHandler::frag_kfree_skb(sk_buff * skb)
{
	if (this_host)
		atomic_sub(skb->truesize, &this_host->ip_frag_mem);
	kfree_skb(skb);
}

void CIP_FragmentHandler::frag_kfree_s(void *ptr, int len)
{
	if (this_host)
		atomic_sub(len, &this_host->ip_frag_mem);
	free(ptr);
}

void * CIP_FragmentHandler::frag_kmalloc(int size)
{
	void *vp = (void *) malloc(size);
	if (!vp)
		return NULL;
	atomic_add(size, &this_host->ip_frag_mem);

	return vp;
}

/* Create a new fragment entry. */
CIP_FragmentHandler::ipfrag * CIP_FragmentHandler::ip_frag_create(int offset, int end, sk_buff * skb, unsigned char *ptr) {
	ipfrag *fp;

	fp = (ipfrag *) frag_kmalloc(sizeof(ipfrag));
	if (fp == NULL) {
		// NETDEBUG(printk("IP: frag_create: no memory left !\n"));
		//nids_params.no_mem("ip_frag_create");
		return (NULL);
	}
	memset(fp, 0, sizeof(ipfrag));

	/* Fill in the structure. */
	fp->offset = offset;
	fp->end = end;
	fp->len = end - offset;
	fp->skb = skb;
	fp->ptr = ptr;

	/* Charge for the SKB as well. */
	this_host->ip_frag_mem += skb->truesize;

	return (fp);
}

int CIP_FragmentHandler::frag_index(ip * iph)
{
	unsigned int ip = ntohl(iph->ip_dst.s_addr);

	return (ip % hash_size);
}

int CIP_FragmentHandler::hostfrag_find(ip * iph)
{
	int hash_index = frag_index(iph);
	hostfrags *hf;

	this_host = 0;
	for (hf = fragtable[hash_index]; hf; hf = hf->next)
		if (hf->ip == iph->ip_dst.s_addr) {
			this_host = hf;
			break;
		}
		if (!this_host)
			return 0;
		else
			return 1;
}

void CIP_FragmentHandler::hostfrag_create(ip * iph)
{
	hostfrags *hf = mknew(hostfrags);
	if (hf == NULL) {
		// Well that's not good...
		assert(false);
		return;
	}
	int hash_index = frag_index(iph);

	hf->prev = 0;
	hf->next = fragtable[hash_index];
	if (hf->next)
		hf->next->prev = hf;
	fragtable[hash_index] = hf;
	hf->ip = iph->ip_dst.s_addr;
	hf->ipqueue = 0;
	hf->ip_frag_mem = 0;
	hf->hash_index = hash_index;
	this_host = hf;
}

void CIP_FragmentHandler::rmthis_host()
{
	int hash_index = this_host->hash_index;

	if (this_host->prev) {
		this_host->prev->next = this_host->next;
		if (this_host->next)
			this_host->next->prev = this_host->prev;
	}
	else {
		fragtable[hash_index] = this_host->next;
		if (this_host->next)
			this_host->next->prev = 0;
	}
	free(this_host);
	this_host = 0;
}

/*
Find the correct entry in the "incomplete datagrams" queue for this
IP datagram, and return the queue entry address if found.
*/
CIP_FragmentHandler::ipq * CIP_FragmentHandler::ip_find(ip * iph)
{
	ipq *qp;
	ipq *qplast;

	qplast = NULL;
	for (qp = this_host->ipqueue; qp != NULL; qplast = qp, qp = qp->next) {
		if (iph->ip_id == qp->iph->ip_id &&
			iph->ip_src.s_addr == qp->iph->ip_src.s_addr &&
			iph->ip_dst.s_addr == qp->iph->ip_dst.s_addr &&
			iph->ip_p == qp->iph->ip_p) {
				del_timer(&qp->timer);	/* So it doesn't vanish on us. The timer will
										be reset anyway */
				return (qp);
		}
	}
	return (NULL);
}

/*
Remove an entry from the "incomplete datagrams" queue, either
because we completed, reassembled and processed it, or because it
timed out.
*/
void CIP_FragmentHandler::ip_free(ipq * qp)
{
	ipfrag *fp;
	ipfrag *xp;

	/* Stop the timer for this entry. */
	del_timer(&qp->timer);

	/* Remove this entry from the "incomplete datagrams" queue. */
	if (qp->prev == NULL) {
		this_host->ipqueue = qp->next;
		if (this_host->ipqueue != NULL)
			this_host->ipqueue->prev = NULL;
		else
			rmthis_host();
	}
	else {
		qp->prev->next = qp->next;
		if (qp->next != NULL)
			qp->next->prev = qp->prev;
	}
	/* Release all fragment data. */
	fp = qp->fragments;
	while (fp != NULL) {
		xp = fp->next;
		frag_kfree_skb(fp->skb);
		frag_kfree_s(fp, sizeof(ipfrag));
		fp = xp;
	}
	/* Release the IP header. */
	frag_kfree_s(qp->iph, 64 + 8);

	/* Finally, release the queue descriptor itself. */
	frag_kfree_s(qp, sizeof(ipq));
}

/* Oops- a fragment queue timed out.  Kill it and send an ICMP reply. */
void CIP_FragmentHandler::ip_expire(CIP_FragmentHandler * thisInstance, ipq *qp)
{
	/* Nuke the fragment queue. */
	thisInstance->ip_free(qp);
}

/*
Memory limiting on fragments. Evictor trashes the oldest fragment
queue until we are back under the low threshold.
*/
void CIP_FragmentHandler::ip_evictor()
{
	// fprintf(stderr, "ip_evict:numpack=%i\n", numpack);
	while (this_host && this_host->ip_frag_mem > IPFRAG_LOW_THRESH) {
		if (!this_host->ipqueue)
			panic("ip_evictor: memcount");
		ip_free(this_host->ipqueue);
	}
}

/*
Add an entry to the 'ipq' queue for a newly received IP datagram.
We will (hopefully :-) receive all other fragments of this datagram
in time, so we just create a queue for this datagram, in which we
will insert the received fragments at their respective positions.
*/
CIP_FragmentHandler::ipq * CIP_FragmentHandler::ip_create(ip * iph)
{
	ipq *qp;
	int ihlen;

	qp = (ipq *) frag_kmalloc(sizeof(ipq));
	if (qp == NULL) {
		// NETDEBUG(printk("IP: create: no memory left !\n"));
		//nids_params.no_mem("ip_create");
		return (NULL);
	}
	memset(qp, 0, sizeof(ipq));

	/* Allocate memory for the IP header (plus 8 octets for ICMP). */
	ihlen = iph->ip_hl * 4;
	qp->iph = (ip *) frag_kmalloc(64 + 8);
	if (qp->iph == NULL) {
		//NETDEBUG(printk("IP: create: no memory left !\n"));
		//nids_params.no_mem("ip_create");
		frag_kfree_s(qp, sizeof(ipq));
		return (NULL);
	}
	memcpy(qp->iph, iph, ihlen + 8);
	qp->len = 0;
	qp->ihlen = (short)ihlen;
	qp->fragments = NULL;
	qp->hf = this_host;

	/* Start a timer for this entry. */
	qp->timer.expires = jiffies() + IP_FRAG_TIME;	/* about 30 seconds     */
	qp->timer.data = qp;	/* pointer to queue     */
	qp->timer.function = &ip_expire;	/* expire function      */
	add_timer(&qp->timer);

	/* Add this entry to the queue. */
	qp->prev = NULL;
	qp->next = this_host->ipqueue;
	if (qp->next != NULL)
		qp->next->prev = qp;
	this_host->ipqueue = qp;

	return (qp);
}

/* See if a fragment queue is complete. */
int CIP_FragmentHandler::ip_done(ipq * qp)
{
	ipfrag *fp;
	int offset;

	/* Only possible if we received the final fragment. */
	if (qp->len == 0)
		return (0);

	/* Check all fragment offsets to see if they connect. */
	fp = qp->fragments;
	offset = 0;
	while (fp != NULL) {
		if (fp->offset > offset)
			return (0);		/* fragment(s) missing */
		offset = fp->end;
		fp = fp->next;
	}
	/* All fragments are present. */
	return (1);
}


/*
Build a new IP datagram from all its fragments.

FIXME: We copy here because we lack an effective way of handling
lists of bits on input. Until the new skb data handling is in I'm
not going to touch this with a bargepole.
*/
char * CIP_FragmentHandler::ip_glue(ipq * qp)
{
	char *skb;
	ip *iph;
	ipfrag *fp;
	unsigned char *ptr;
	int count, len;

	/* Allocate a new buffer for the datagram. */
	len = qp->ihlen + qp->len;

	if (len > 65535) {
		// NETDEBUG(printk("Oversized IP packet from %s.\n", int_ntoa(qp->iph->ip_src.s_addr)));
		//((int (__cdecl*)(int,int,ip*,void*))nids_params.syslog)(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, qp->iph, 0);
		ip_free(qp);
		return NULL;
	}
	if ((skb = (char *) malloc(len)) == NULL) {
		// NETDEBUG(printk("IP: queue_glue: no memory for gluing queue %p\n", qp));
		//nids_params.no_mem("ip_glue");
		ip_free(qp);
		return (NULL);
	}
	/* Fill in the basic details. */
	ptr = (unsigned char *)skb;
	memcpy(ptr, ((unsigned char *) qp->iph), qp->ihlen);
	ptr += qp->ihlen;
	count = 0;

	/* Copy the data portions of all fragments into the new buffer. */
	fp = qp->fragments;
	while (fp != NULL) {
		if (fp->len < 0 || fp->offset + qp->ihlen + fp->len > len) {
			//NETDEBUG(printk("Invalid fragment list: Fragment over size.\n"));
			//((int (__cdecl*)(int,int,ip*,void*))nids_params.syslog)(NIDS_WARN_IP, NIDS_WARN_IP_INVLIST, qp->iph, 0);
			ip_free(qp);
			//kfree_skb(skb, FREE_WRITE);
			//ip_statistics.IpReasmFails++;
			free(skb);
			return NULL;
		}
		memcpy((ptr + fp->offset), fp->ptr, fp->len);
		count += fp->len;
		fp = fp->next;
	}
	/* We glued together all fragments, so remove the queue entry. */
	ip_free(qp);

	/* Done with all fragments. Fixup the new IP header. */
	iph = (ip *) skb;
	iph->ip_off = 0;
	iph->ip_len = htons((u_short)((iph->ip_hl * 4) + count));
	// skb->ip_hdr = iph;

	return (skb);
}

/* Process an incoming IP datagram fragment. */
char * CIP_FragmentHandler::ip_defrag(ip *iph, sk_buff *skb, u_int * nidsFlags) {
	ipfrag *prev, *next, *tmp;
	ipfrag *tfp;
	ipq *qp;
	char *skb2;
	unsigned char *ptr;
	int flags, offset;
	int i, ihl, end;

	if (!hostfrag_find(iph) && skb)
		hostfrag_create(iph);

	/* Start by cleaning up the memory. */
	if (this_host)
		if (this_host->ip_frag_mem > IPFRAG_HIGH_THRESH)
			ip_evictor();

	/* Find the entry of this IP datagram in the "incomplete datagrams" queue. */
	if (this_host)
		qp = ip_find(iph);
	else
		qp = 0;

	/* Is this a non-fragmented datagram? */
	offset = ntohs(iph->ip_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	if (((flags & IP_MF) == 0) && (offset == 0)) {
		if (qp != NULL)
			ip_free(qp);		/* Fragmented frame replaced by full
								unfragmented copy */
		return 0;
	}

	/* ip_evictor() could have removed all queues for the current host */
	if (!this_host)
		hostfrag_create(iph);

	offset <<= 3;			/* offset is in 8-byte chunks */
	ihl = iph->ip_hl * 4;

	/*
	If the queue already existed, keep restarting its timer as long as
	we still are receiving fragments.  Otherwise, create a fresh queue
	entry.
	*/
	if (qp != NULL) {
		/* ANK. If the first fragment is received, we should remember the correct
		IP header (with options) */
		if (offset == 0) {
			qp->ihlen = (short)ihl;
			memcpy(qp->iph, iph, ihl + 8);
		}

		del_timer(&qp->timer);
		qp->timer.expires = jiffies() + IP_FRAG_TIME;	/* about 30 seconds */
		qp->timer.data = qp;	/* pointer to queue */
		qp->timer.function = &ip_expire;	/* expire function */
		add_timer(&qp->timer);
	}
	else {
		/* If we failed to create it, then discard the frame. */
		if ((qp = ip_create(iph)) == NULL) {
			kfree_skb(skb);
			return NULL;
		}
	}

	/* Attempt to conan oversize packet. */
	assert(offset >= 0);
	if (ntohs(iph->ip_len) + (int) offset > 65535) {
		// NETDEBUG(printk("Oversized packet received from %s\n", int_ntoa(iph->ip_src.s_addr)));
		//((int (__cdecl*)(int,int,ip*,void*))nids_params.syslog)(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, iph, 0);
		kfree_skb(skb);
		return NULL;
	}
	/* Determine the position of this fragment. */
	end = offset + ntohs(iph->ip_len) - ihl;

	/* Point into the IP datagram 'data' part. */
	ptr = (unsigned char *)(skb->data + ihl);

	/* Is this the final fragment? */
	if ((flags & IP_MF) == 0)
		qp->len = end;

	/*
	Find out which fragments are in front and at the back of us in the
	chain of fragments so far.  We must know where to put this
	fragment, right?
	*/
	prev = NULL;
	for (next = qp->fragments; next != NULL; next = next->next) {
		if (next->offset >= offset)
			break;			/* bingo! */
		prev = next;
	}

	// IP fragment arrived out of order
	if (next != NULL && nidsFlags != NULL) {
		*nidsFlags |= NIDS_OUT_OF_ORDER;
	}

	/*
	We found where to put this one.  Check for overlap with preceding
	fragment, and, if needed, align things so that any overlaps are
	eliminated.
	*/
	if (prev != NULL && offset < prev->end) {
		//((int (__cdecl*)(int,int,ip*,void*))nids_params.syslog)(NIDS_WARN_IP, NIDS_WARN_IP_OVERLAP, iph, 0);
		i = prev->end - offset;
		offset += i;		/* ptr into datagram */
		ptr += i;			/* ptr into fragment data */
	}
	/*
	Look for overlap with succeeding segments.
	If we can merge fragments, do it.
	*/
	for (tmp = next; tmp != NULL; tmp = tfp) {
		tfp = tmp->next;
		if (tmp->offset >= end)
			break;			/* no overlaps at all */
		//((int (__cdecl*)(int,int,ip*,void*))nids_params.syslog)(NIDS_WARN_IP, NIDS_WARN_IP_OVERLAP, iph, 0);

		i = end - next->offset;	/* overlap is 'i' bytes */
		tmp->len -= i;		/* so reduce size of    */
		tmp->offset += i;		/* next fragment        */
		tmp->ptr += i;
		/*
		If we get a frag size of <= 0, remove it and the packet that it
		goes with. We never throw the new frag away, so the frag being
		dumped has always been charged for.
		*/
		if (tmp->len <= 0) {
			if (tmp->prev != NULL)
				tmp->prev->next = tmp->next;
			else
				qp->fragments = tmp->next;

			if (tmp->next != NULL)
				tmp->next->prev = tmp->prev;

			next = tfp;		/* We have killed the original next frame */

			frag_kfree_skb(tmp->skb);
			frag_kfree_s(tmp, sizeof(ipfrag));
		}
	}
	/* Insert this fragment in the chain of fragments. */
	tfp = NULL;
	tfp = ip_frag_create(offset, end, skb, ptr);

	/*
	No memory to save the fragment - so throw the lot. If we failed
	the frag_create we haven't charged the queue.
	*/
	if (!tfp) {
		//nids_params.no_mem("ip_defrag");
		kfree_skb(skb);
		return NULL;
	}
	/* From now on our buffer is charged to the queues. */
	tfp->prev = prev;
	tfp->next = next;
	if (prev != NULL)
		prev->next = tfp;
	else
		qp->fragments = tfp;

	if (next != NULL)
		next->prev = tfp;

	/*
	OK, so we inserted this new fragment into the chain.  Check if we
	now have a full IP datagram which we can bump up to the IP
	layer...
	*/
	if (ip_done(qp)) {
		skb2 = ip_glue(qp);		/* glue together the fragments */
		return (skb2);
	}
	return (NULL);
}

int CIP_FragmentHandler::ip_defrag_stub(ip *iph, ip **defrag, u_int * nidsFlags, nids_prm *nids_params) {
	int offset, flags, tot_len;
	sk_buff *skb;

	numpack++;
	timenow = 0;
	
	while (timer_head && timer_head->expires < jiffies()) {
		this_host = ((ipq *) (timer_head->data))->hf;
		timer_head->function(this, timer_head->data);
	}

	offset  = ntohs(iph->ip_off);
	flags   = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	
	// Make sure this is really fragmented
	if (((flags & IP_MF) == 0) && (offset == 0)) {
		ip_defrag(iph, 0, nidsFlags);
		return IPF_NOTF;
	}
	
	tot_len = ntohs(iph->ip_len);
	skb = (sk_buff *) malloc(tot_len + sizeof(sk_buff));
	if (!skb)
		nids_params->no_mem("ip_defrag_stub");

	skb->data = (char *) (skb + 1);
	memcpy(skb->data, iph, tot_len);
	skb->truesize = tot_len + 16 + nids_params->dev_addon;
	skb->truesize = (skb->truesize + 15) & ~15;
	skb->truesize += nids_params->sk_buff_size;

	*defrag = (ip *)ip_defrag((ip *) (skb->data), skb, nidsFlags);
	if (*defrag)
		return IPF_NEW;

	return IPF_ISF;
}

void CIP_FragmentHandler::ip_frag_init(int n, nids_prm *nids_params) {

#ifndef WIN32
	timeval tv;
	gettimeofday(&tv, 0);
	time0 = tv.tv_sec;
#else
	SYSTEMTIME st;
	GetSystemTime(&st);
	time0 = st.wSecond;
#endif

	fragtable = (hostfrags **) calloc(n, sizeof(hostfrags *));
	if (!fragtable)
		nids_params->no_mem("ip_frag_init");
	hash_size = n;
}

void CIP_FragmentHandler::ip_frag_exit()
{
	if (fragtable) {
		free(fragtable);
		fragtable = NULL;
	}
	/* FIXME: do we need to free anything else? */
}
