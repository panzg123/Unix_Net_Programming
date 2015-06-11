/*
 * sip_skbuff.h
 *
 *  Created on: 2015-6-1
 *      Author: panzg
 */

#ifndef SIP_SKBUFF_H_
#define SIP_SKBUFF_H_


#include "sip_ether.h"
#include "sip_skbuff.h"
#include "sip_arp.h"
#include "sip_ip.h"
#include "sip_icmp.h"
#include "sip_tcp.h"
#include "sip_udp.h"
#define CHECKSUM_NONE 0
#define CHECKSUM_HW 1
#define CHECKSUM_UNNECESSARY 2
struct sip_tcphdr;
struct sip_udphdr;
struct sip_icmphdr;
struct sip_igmphdr;
struct sip_iphdr;
struct sip_arphdr;
struct sip_ethhdr;
struct net_device;

struct skbuff {
	struct skbuff *next;				/*下一个skbuff结构*/

	union 							/*传输层枚举变量*/
	{
		struct sip_tcphdr		*tcph;	/*tcp协议的头部指针*/
		struct sip_udphdr		*udph;	/*udp协议的头部指针*/
		struct sip_icmphdr		*icmph;	/*icmp协议的头部指针*/
		struct sip_igmphdr	*igmph;	/*igmp协议的头部指针*/
		__u8				*raw;	/*传输层原始数据指针*/
	} th;							/*传输层变量*/

	union 							/*网络层枚举变量*/
	{
		struct sip_iphdr		*iph;	/*ip协议的头部指针*/
		struct sip_arphdr		*arph;	/*arp协议的头部指针*/
		__u8				*raw;	/*网络层原始数据指针*/
	} nh;							/*网络层变量*/

	union 							/*物理层枚举变量*/
	{
		struct sip_ethhdr		*ethh;	/*物理层的以太网头部*/
	  	__u8 				*raw;	/*物理层的原始数据指针*/
	} phy;							/*物理层变量*/

	struct net_device  		*dev;	/*网卡设备*/
	__be16		protocol;	/*协议类型*/
	__u32 		tot_len;		/*skbuff中网络数据的总长度*/
	__u32 		len;  		/*skbuff中当前协议层的数据长度*/

	__u8 		csum;		/*校验和*/
	__u8		ip_summed;	/*ip层头部是否进行了校验*/
	__u8		*head,		/*实际网络数据的头部指针*/
				*data,		/*当前层网络数据的头部指针*/
				*tail,		/*当前层数据的尾部指针*/
				*end;		/*实际网络数据的尾部部指针*/
};

struct sip_sk_buff_head {
	struct skbuff	*next;
	struct skbuff	*prev;

	__u32		qlen;
};

#include <semaphore.h>
/** A sock descriptor */
struct sock {
	int type;					/*协议类型*/
	int state;				/*协议的状态*/
	union
	{
		struct ip_pcb  *ip;		/*IP层的控制结构*/
		struct tcp_pcb *tcp;	/*TCP层的控制结构*/
		struct udp_pcb *udp;	/*UDP的控制结构*/
	} pcb;
	int err;					/*错误值*/
	struct skbuff *skb_recv;	/*接收缓冲区*/

	sem_t sem_recv;			/*接收缓冲区计数信号量*/
	int socket;				/*这个sock对应的文件描述符值*/
	int recv_timeout;			/*接收数据超时时间*/
	__u16 recv_avail;		/*可以接收数据*/
};




#endif /* SIP_SKBUFF_H_ */
