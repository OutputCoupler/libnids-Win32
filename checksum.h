#ifndef _NIDS_CHECKSUM_H
#define _NIDS_CHECKSUM_H

unsigned short ip_check_ext(register unsigned short *addr, register int len, int addon);
unsigned short ip_compute_csum(unsigned short *addr, int len);

#endif /* _NIDS_CHECKSUM_H */
