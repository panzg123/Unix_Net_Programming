#ifndef __SIP_IGMP_H__
#define __SIP_IGMP_H__
struct sip_igmphdr
{
	__u8 type;
	__u8 code;		/* For newer IGMP */
	__u16 csum;
	__u32 group;
};

#endif /*__SIP_IGMP_H__*/
