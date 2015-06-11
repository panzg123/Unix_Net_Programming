/*
 * sip_ip.h
 *
 *  Created on: 2015-6-2
 *      Author: panzg
 */

#ifndef SIP_IP_H_
#define SIP_IP_H_

#define IPHDR_LEN 20

enum {
  SIP_IPPROTO_IP = 0,		/* Dummy protocol for TCP		*/
  SIP_IPPROTO_ICMP = 1,		/* Internet Control Message Protocol	*/
  SIP_IPPROTO_IGMP = 2,		/* Internet Group Management Protocol	*/
  SIP_IPPROTO_IPIP = 4,		/* IPIP tunnels (older KA9Q tunnels use 94) */
  SIP_IPPROTO_TCP = 6,		/* Transmission Control Protocol	*/
  SIP_IPPROTO_EGP = 8,		/* Exterior Gateway Protocol		*/
  SIP_IPPROTO_PUP = 12,		/* PUP protocol				*/
  SIP_IPPROTO_UDP = 17,		/* User Datagram Protocol		*/
  SIP_IPPROTO_IDP = 22,		/* XNS IDP protocol			*/
  SIP_IPPROTO_DCCP = 33,		/* Datagram Congestion Control Protocol */
  SIP_IPPROTO_RSVP = 46,		/* RSVP protocol			*/
  SIP_IPPROTO_GRE = 47,		/* Cisco GRE tunnels (rfc 1701,1702)	*/

  SIP_IPPROTO_IPV6	 = 41,		/* IPv6-in-IPv4 tunnelling		*/

  SIP_IPPROTO_ESP = 50,            /* Encapsulation Security Payload protocol */
  SIP_IPPROTO_AH = 51,             /* Authentication Header protocol       */
  SIP_IPPROTO_PIM    = 103,		/* Protocol Independent Multicast	*/

  SIP_IPPROTO_COMP   = 108,                /* Compression Header protocol */
  SIP_IPPROTO_SCTP   = 132,		/* Stream Control Transport Protocol	*/

  SIP_IPPROTO_RAW	 = 255,		/* Raw IP packets			*/
  SIP_IPPROTO_MAX
};
#define IP_MAX_TTL 255

struct sip_iphdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	     __u8	tos;
		__be16	tot_len;
		__be16	id;
		__be16	frag_off;
		__u8	ttl;
		__u8	protocol;
		__u16	check;
		__be32	saddr;
		__be32	daddr;
		/*The options start here. */
};

#define IP_IS_MULTICAST(ip) (((ip) & ntohl(0xf0000000UL)) == ntohl(0xe0000000UL))
#define IP_IS_LINKLOCAL(ip) (((ip) & ntohl(0xffff0000UL)) == ntohl(0xa9fe0000UL))
#define IP_ADDR_ANY_VALUE 0x00000000UL
#define IP_ADDR_BROADCAST_VALUE 0xffffffffUL

/* IP reassembly helper struct.
 * This is exported because memp needs to know the size.
 */
struct sip_reass
{
  	struct sip_reass 	*next;				/*下一个重组指针*/
  	struct skbuff 		*skb;				/*分片的头指针*/
  	struct iphdr 		iphdr;				/*IP头部结构*/
  	__u16 			datagram_len;		/*数据报文的长度*/
  	__u8 			flags;				/*重组的状态*/
  	__u8 			timer;				/*时间戳*/
};

#endif /* SIP_IP_H_ */
