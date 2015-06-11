#ifndef __SIP_TCP_H__
#define __SIP_TCP_H__


struct sip_tcphdr {
	__u16	source;
	__u16	dest;
	__u32	seq;
	__u32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__u16	window;
	__u16	check;
	__u16	urg_ptr;
};


#endif /*__SIP_TCP_H__*/
