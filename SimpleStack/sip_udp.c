/*
 * sip_udp.c
 *
 *  Created on: 2015-6-11
 *      Author: panzg
 */


#include "sip.h"

#define UDP_HTABLE_SIZE 128						/*UDP控制单元的大小*/
static struct udp_pcb *udp_pcbs[UDP_HTABLE_SIZE];	/*UDP控制单元数组*/
static __u16 found_a_port()
{
	static __u32 index = 0x0;				/*静态变量,用于保存当前已经分配的端口*/
	index ++;							/*增加端口值*/
	return (__u16)(index&0xFFFF);			/*返回16为的端口值*/
}


struct udp_pcb *SIP_UDPNew(void)
{
	struct udp_pcb *pcb = NULL;				/*pcb变量*/
	pcb = (struct udp_pcb *)malloc(sizeof(struct udp_pcb));/*申请变量*/
	if (pcb != NULL) 							/*申请成功*/
	{
		memset(pcb, 0, sizeof(struct udp_pcb));	/*初始化为0*/
		pcb->ttl = 255;						/*设置生存空间为255*/
	}

	return pcb;								/*返回pcb指针*/
}

void SIP_UDPRemove(struct udp_pcb *pcb)
{
	struct udp_pcb *pcb_t;
	int i = 0;

	if(!pcb){								/*pcb为空*/
		return;
	}

	pcb_t = udp_pcbs[pcb->port_local%UDP_HTABLE_SIZE];/*返回端口值的hash表位置控制结构*/
	if(!pcb_t){								/*为空*/
		;
	}else if(pcb_t == pcb)	{					/*为当前控制结构*/
		udp_pcbs[pcb->port_local%UDP_HTABLE_SIZE] = pcb_t->next;/*从控制链表中摘除结构*/
	}else{									/*头部不是控制结构*/
		for (; pcb_t->next != NULL; pcb_t = pcb_t->next) /*查找匹配项*/
		{
			if (pcb_t->next == pcb) 			/*找到*/
			{
				pcb_t->next = pcb->next;		/*从控制链表中摘除结构*/
			}
		}
	}

	free(pcb);								/*释放资源*/
}


int SIP_UDPBind(struct udp_pcb *pcb,
			struct in_addr *ipaddr,
			__u16 port)
{
	struct udp_pcb *ipcb;
	__u8 rebind;

	rebind = 0;
	/* 查找udp_pcbs中是否已经存在这个控制单元 */
	for (ipcb = udp_pcbs[port&(UDP_HTABLE_SIZE-1)]; ipcb != NULL; ipcb = ipcb->next)
	{
		if (pcb == ipcb) 						/*已经存在*/
		{
			rebind = 1;						/*已经绑定*/
		}
	}

	pcb->ip_local.s_addr= ipaddr->s_addr;

	if (port == 0) 							/*还没有指定端口地址*/
	{
#define UDP_PORT_RANGE_START 4096
#define UDP_PORT_RANGE_END   0x7fff
		port = found_a_port();				/*生成端口*/
		ipcb = udp_pcbs[port];
		/*遍历控制链表中的单元是否已经使用这个端口地址*/
		while ((ipcb!=NULL)&&(port != UDP_PORT_RANGE_END) )
		{
			if (ipcb->port_local == port) 		/*已经使用此端口*/
			{
				port = found_a_port();		/*重新生成端口地址*/
				ipcb = udp_pcbs[port];		/*重新扫描*/
			}else{
				ipcb = ipcb->next;				/*下一个*/
			}
		}

		if (ipcb != NULL) 						/*没有合适的端口*/
		{
			return -1;						/*返回错误值*/
		}
	}

	pcb->port_local = port;					/*绑定合适的端口值*/
	if (rebind == 0) 							/*还没有将此控制单元加入链表*/
	{
		pcb->next = udp_pcbs[port];			/*放到控制单元链表的hash位置头部*/
		udp_pcbs[port] = pcb;				/*更新头指针*/
	}

	return 0;
}


int SIP_UDPConnect(struct udp_pcb *pcb,
					struct in_addr *ipaddr,
					__u16 port)
{
	struct udp_pcb *ipcb;

	if (pcb->port_local == 0) 					/*还没有绑定端口地址*/
	{
		int err = SIP_UDPBind(pcb, &pcb->ip_local, 0);/*绑定端口*/
		if (err != 0)
			return err;
	}

	pcb->ip_remote.s_addr = ipaddr->s_addr;	/*目的IP地址*/
	pcb->port_remote = port;					/*目的端口*/

	/* 将UDP的PCB加入PCB链表中*/
	for (ipcb = udp_pcbs[pcb->port_local]; ipcb != NULL; ipcb = ipcb->next)
	{
		if (pcb == ipcb) 						/*已经存在于链表中*/
		{
			return 0;
		}
	}

	/*这个PCB控制单元还没有加入链表中，将此单元加入到链表的头部*/
	pcb->next = udp_pcbs[pcb->port_local];
	udp_pcbs[pcb->port_local] = pcb;

	return 0;
}


void SIP_UDPDisconnect(struct udp_pcb *pcb)
{
	/* reset remote address association */
	pcb->ip_remote.s_addr = INADDR_ANY;
	pcb->port_remote = 0;
	/* mark PCB as unconnected */
	pcb->flags &= ~UDP_FLAGS_CONNECTED;
}



int SIP_UDPSendTo(struct net_device *dev,
	struct udp_pcb *pcb,
	struct skbuff *skb,
	struct in_addr *dst_ip, __u16 dst_port)
{
	struct sip_udphdr *udphdr;
	struct in_addr *src_ip;
	int err;

	/*如果此PCB还没有绑定端口,进行端口绑定*/
	if (pcb->port_local == 0) 								/*还没有绑定端口*/
	{
		err = SIP_UDPBind(pcb, &pcb->ip_local, pcb->port_local);/*绑定端口*/
		if (err != 0)
		{
			return err;
		}
	}

	udphdr = skb->th.udph;					/*UDP头部指针*/
	udphdr->source = htons(pcb->port_local);	/*UDP源端口*/
	udphdr->dest = htons(dst_port);			/*UDP目的端口*/
	udphdr->check= 0x0000; 					/*先将UDP的校验和设置为0*/

	/* PCB本地地址为 IP_ANY_ADDR? */
	if (pcb->ip_local.s_addr == 0)
	{
		src_ip = &dev->ip_host;				/*将源地址设置为本机IP地址*/
	} 	else 	{
		src_ip = &(pcb->ip_local);				/*用PCB中的IP地址作为源IP地址*/
	}

	udphdr->len = htons(skb->len);				/*UDP的头部长度*/
	/* 计算校验和 */
	if ((pcb->flags & UDP_FLAGS_NOCHKSUM) == 0)
	{
		udphdr->check= SIP_ChksumPseudo(skb, src_ip, dst_ip, IPPROTO_UDP, skb->len);
		if (udphdr->check == 0x0000)
			udphdr->check = 0xffff;
	}

	/*调用UDP的发送函数将数据发送出去*/
	err = SIP_UDPSendOutput(skb, src_ip, dst_ip, pcb->ttl, pcb->tos, IPPROTO_UDP);

	return err;
}

int  SIP_UDPSend(struct net_device *dev,struct udp_pcb *pcb, struct skbuff *skb)
{
 	/* send to the packet using remote ip and port stored in the pcb */
	return SIP_UDPSendTo(dev, pcb,skb, &pcb->ip_remote, pcb->port_remote);
}
#include <semaphore.h>
#include <pthread.h>
int SIP_UDPInput(struct net_device *dev, struct skbuff *skb)
{
	__u16 port = ntohs(skb->th.udph->dest);

	struct udp_pcb *upcb = NULL;
	/*根据端口地址查找控制链表结构中的控制单元*/
	for(upcb = udp_pcbs[port%UDP_HTABLE_SIZE]; upcb != NULL; upcb = upcb->next)
	{
		if(upcb->port_local== port)				/*找到*/
			break;
	}

	if(!upcb)
		return 0;

	struct sock *sock = upcb->sock;			/*协议无关层的结构*/
	if(!sock)
		return 1;

	struct skbuff *recvl = sock->skb_recv;		/*接收缓冲区链表头指针*/
	if(!recvl)									/*为空?*/
	{
		sock->skb_recv = skb;					/*挂接到头部*/
		skb->next = NULL;
	}
	else
	{
		for(; recvl->next != NULL; upcb = upcb->next)/*到尾部*/
			;
		recvl->next = skb;					/*在尾部挂接*/
		skb->next = NULL;
	}

	sem_post(&sock->sem_recv);				/*接收缓冲区计数值增加*/
}


int SIP_UDPSendOutput(struct net_device *dev, struct skbuff *skb,struct udp_pcb *pcb,
	struct in_addr *src, struct in_addr *dest)
{
	ip_output(dev,skb, src, dest, pcb->ttl, pcb->tos, IPPROTO_UDP);
}

