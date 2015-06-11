/*
 * sip_arp.h
 *
 *  Created on: 2015-6-2
 *      Author: panzg
 */

#ifndef SIP_ARP_H_
#define SIP_ARP_H_

#define	ARPOP_REQUEST	1		/* ARP 请求*/
#define	ARPOP_REPLY 	2		/* ARP 应答*/
#define 	ETH_P_802_3	0x0001

#define 	ARP_TABLE_SIZE 10		/*映射表大小*/
#define 	ARP_LIVE_TIME	20		/*ARP映射表生存时间*/
enum arp_status
{
	ARP_EMPTY,					/*ARP状态为空*/
	ARP_ESTABLISHED			/*ARP已经映射表项建立*/
};

struct arpt_arp					/*ARP表项结构*/
{
	__u32	ipaddr;				/*IP地址*/
	__u8	ethaddr[ETH_ALEN];	/*MAC地址*/
  	time_t 	ctime;				/*最后更新时间*/
	enum 	arp_status status;		/*ARP状态值*/
};


struct sip_arphdr
{
	 /*	 以下为ARP头部结构*/
	__be16	ar_hrd;				/* 硬件地址类型*/
	__be16	ar_pro;				/* 协议地址类型*/
	__u8	ar_hln;				/* 硬件地址长度*/
	__u8	ar_pln;				/* 协议地址长度*/
	__be16	ar_op;				/* ARP操作码*/

	 /*	 以下为以太网中的ARP内容*/
	__u8 	ar_sha[ETH_ALEN];	/* 发送方的硬件地址*/
	__u8 	ar_sip[4];			/* 发送方的IP地址*/
	__u8 	ar_tha[ETH_ALEN];	/* 目的硬件地址*/
	__u8 	ar_tip[4];			/* 目的IP地址*/
};




#endif /* SIP_ARP_H_ */
