/*
 * sip_arp.c
 *
 *  Created on: 2015-6-2
 *      Author: panzg
 */

#include"sip.h"

static struct arpt_arp arp_table[ARP_TABLE_SIZE];

/*
 * 对整个映射表进行初始化
 */
void Init_arp_entry()
{
	int i=0;
	for (i = 0; i < ARP_TABLE_SIZE; ++i)  /*初始化整个arp映射表*/
	{
		   arp_table[i].ctime = 0;						/*初始时间值为0*/
			memset(arp_table[i].ethaddr, 0, ETH_ALEN);		/*MAC地址为0*/
			arp_table[i].ipaddr = 0;						/*IP地址为0*/
			arp_table[i].status = ARP_EMPTY;				/*表项状态为空*/
	}
}

/*
 * 根据输入的IP地址进行查找映射表
 */
struct arpt_arp* arp_find_entry(__u32 ip)
{
	int i = -1;
	struct arpt_arp*found = NULL;
	for(i = 0; i<ARP_TABLE_SIZE; i++)					/*在ARP表中查找IP匹配项*/
	{
		if(arp_table[i].ctime >  time(NULL) + ARP_LIVE_TIME)/*查看是否表项超时*/
			arp_table[i].status = ARP_EMPTY;			/*超时,置空表项*/
		else if(arp_table[i].ipaddr == ip 				/*没有超时,查看是否IP地址匹配*/
			&& arp_table[i].status == ARP_ESTABLISHED)	/*并且状态为已经建立*/
		{
			found = &arp_table[i];						/*找到一个合适的表项*/
			break;									/*退出查找过程*/
		}
	}

	return found;
}

/*
 * 更新映射表
 */
struct arpt_arp * update_arp_entry(__u32 ip, __u8 * ethaddr)
{
	struct arpt_arp  *found = NULL;
	found = arp_find_entry(ip);						/*根据IP查找ARP表项*/
	if(found){										/*找到对应表项*/
		memcpy(found->ethaddr, ethaddr, ETH_ALEN);	/*将给出的硬件地址拷贝到表项中*/
		found->status = ARP_ESTABLISHED;				/*更新ARP的表项状态*/
		found->ctime = time(NULL);						/*更新表项的最后更新时间*/
	}

	return found;
}

/*
 * 向映射表中增加新的IP/MAC对
 */
void arp_add_entry(__u32 ip,__u8 *ethaddr,int status)
{
	int i=0;
	struct arpt_arp * found = NULL;
	found = update_arp_entry(ip,ethaddr);   /*更新arp表项*/
	if(!found)  /*更新不成功*/
	{
		for(i = 0; i<ARP_TABLE_SIZE; i++)  /*插入空白表项*/
				{
					if(arp_table[i].status == ARP_EMPTY)		/*映射项为空*/
					{
						found = &arp_table[i];					/*重置found变量*/
						break;								/*退出查找*/
					}
				}
	}
	if(found){										/*对此项进行更新*/
			found->ipaddr = ip;							/*IP地址更新*/
			memcpy(found->ethaddr, ethaddr, ETH_ALEN);	/*MAC地址更新*/
			found->status = status;						/*状态更新*/
			found->ctime = time(NULL);						/*最后更新时间更新*/
		}
}


/*
 *创建ARP网络报文
 */
struct skbuff* arp_create(struct net_device *dev,   /*设备*/
		int type,                          /*arp协议的类型*/
		__u32 src_ip,                   /*源主机IP*/
		__u32 dest_ip,                /*目的主机IP*/
		__u8* src_hw,                 /*源主机MAC*/
		__u8* dest_hw,             /*目的主机MAC*/
		__u8* target_hw)         /*解析的主机MAC*/
{
	struct skbuff* skb;
	struct sip_arphdr*  arph;
	DBGPRINT(DBG_LEVEL_TRACE,"==>arp_create\n");

	//请求一个skbuff结构
	skb = skb_alloc(ETH_ZLEN);
	if(skb == NULL )
	{
		goto EXITarp_create;;
	}

	   skb->phy.raw = skb_put(skb,sizeof(struct sip_ethhdr));	/*更新物理层头部指针位置*/
		skb->nh.raw = skb_put(skb,sizeof(struct sip_arphdr));	/*更新网络层头部指针位置*/
		arph = skb->nh.arph;								/*设置ARP头部指针,便于操作*/
		skb->dev = dev;									/*设置网络设备指针*/
		if (src_hw == NULL)								/*以太网源地址为空*/
			src_hw = dev->hwaddr;						/*源地址设置为网络设备的硬件地址*/
		if (dest_hw == NULL)								/*以太网目的地址为空*/
			dest_hw = dev->hwbroadcast;					/*目的地址设置为以太网广播硬件地址*/

		skb->phy.ethh->h_proto = htons(ETH_P_ARP);			/*物理层网络协议设置为ARP协议*/
		memcpy(skb->phy.ethh->h_dest, dest_hw, ETH_ALEN);	/*设置报文的目的硬件地址*/
		memcpy(skb->phy.ethh->h_source, src_hw, ETH_ALEN);/*设置报文的源硬件地址*/

		arph->ar_op = htons(type);							/*设置ARP操作类型*/
		arph->ar_hrd = htons(ETH_P_802_3);					/*设置ARP的硬件地址类型为802.3*/
		arph->ar_pro =  htons(ETH_P_IP);					/*设置ARP的协议地址类型为IP*/
		arph->ar_hln = ETH_ALEN;							/*设置ARP头部的硬件地址长度为6*/
		arph->ar_pln = 4;									/*设置ARP头部的协议地址长度为4*/

		memcpy(arph->ar_sha, src_hw, ETH_ALEN);			/*ARP报文的源硬件地址*/
		memcpy(arph->ar_sip,  (__u8*)&src_ip, 4);			/*ARP报文的源IP地址*/
		memcpy(arph->ar_tip, (__u8*)&dest_ip, 4);			/*ARP报文的目的IP地址*/
		if (target_hw != NULL)							/*如果目的硬件地址不为空*/
			memcpy(arph->ar_tha, target_hw, dev->hwaddr_len);/*ARP报文的目的硬件地址*/
		else												/*没有给出目的硬件地址*/
			memset(arph->ar_tha, 0, dev->hwaddr_len);		/*目的硬件地址留白*/

	EXITarp_create:
	    DBGPRINT(DBG_LEVEL_TRACE,"<==arp_create\n");
	    return skb;
}

/*
 * 发送arp应答包
 */
void arp_send(struct net_device *dev, 				/*设备*/
				int type, 								/*ARP协议的类型*/
				__u32 src_ip,							/*源主机IP*/
				__u32 dest_ip,						/*目的主机IP*/
				__u8* src_hw,						/*源主机MAC*/
				__u8* dest_hw, 						/*目的主机MAC*/
				__u8* target_hw)						/*解析的主机MAC*/
{
	struct skbuff *skb;
	DBGPRINT(DBG_LEVEL_TRACE,"==>arp_send\n");
	/*建立一个ARP网络报文*/
	skb = arp_create(dev,type,src_ip,dest_ip,src_hw,dest_hw,target_hw);
	if(skb)											/*建立成功*/
	{
		dev->linkoutput(skb, dev);						/*调用底层的网络发送函数*/
	}
	DBGPRINT(DBG_LEVEL_TRACE,"<==arp_send\n");
}

/*
 * 向某个ip发送arp请求包
 */
void arp_request(struct net_device *dev,__u32 ip)
{
	struct skbuff *skb;
	DBGPRINT(DBG_LEVEL_TRACE,"==>arp_request\n");
	__u32 tip = 0;
	/*查看请求的IP地址和本机IP地址是否在同一个自网上*/
	if( (ip & dev->ip_netmask.s_addr) 					/*请求的IP地址*/
		== 											/*同一子网*/
		(dev->ip_host.s_addr & dev->ip_netmask.s_addr ) )/*本机的IP地址*/
	{
		tip = ip;										/*同一子网,此IP为目的IP*/
	}
	else												/*不同子网*/
	{
		tip = dev->ip_gw.s_addr;						/*目的IP为网关地址*/
	}
	/*建立一个ARP请求报文,其中的目的IP为上述地址*/
	skb = arp_create(dev,
					ARPOP_REQUEST,
					dev->ip_host.s_addr,
					tip,
					dev->hwaddr,
					NULL,
					NULL);
	if(skb)											/*建立skbuff成功*/
	{
		dev->linkoutput(skb, dev);						/*通过底层网络函数发送*/
	}
	DBGPRINT(DBG_LEVEL_TRACE,"<==arp_request\n");
}

int arp_input(struct skbuff **pskb,struct net_device *dev)
{
	struct skbuff *skb = *pskb;

		__be32 ip = 0;
		DBGPRINT(DBG_LEVEL_TRACE,"==>arp_input\n");
		if(skb->tot_len < sizeof(struct sip_arphdr))			/*接收到的网络数据总长度小于ARP头部长度*/
		{
			goto EXITarp_input;							/*错误,返回*/
		}

		ip = *(__be32*)(skb->nh.arph->ar_tip) ;				/*ARP请求的目的地址*/
		if(ip == dev->ip_host.s_addr)						/*为本机IP?*/
		{
			update_arp_entry(ip, dev->hwaddr);			/*更新ARP表*/
		}

		switch(ntohs(skb->nh.arph->ar_op))					/*查看ARP头部协议类型*/
		{
			case ARPOP_REQUEST:							/*ARP请求类型*/
			{
				struct in_addr t_addr;
				t_addr.s_addr = *(unsigned int*)skb->nh.arph->ar_sip;/*ARP请求源IP地址*/
				DBGPRINT(DBG_LEVEL_ERROR,"ARPOP_REQUEST, FROM:%s\n",inet_ntoa(t_addr));

				/*向ARP请求的IP地址发送应答*/
				arp_send(dev,
						ARPOP_REPLY,
						dev->ip_host.s_addr,
						*(__u32*)skb->nh.arph->ar_sip,
						dev->hwaddr,
						skb->phy.ethh->h_source,
						skb->nh.arph->ar_sha);
				/*将此项ARP映射内容加入映射表*/
				arp_add_entry(*(__u32*)skb->nh.arph->ar_sip, skb->phy.ethh->h_source, ARP_ESTABLISHED);
			}
				break;
			case ARPOP_REPLY:							/*ARP应答类型*/
				/*将此项ARP映射内容加入映射表*/
				arp_add_entry(*(__u32*)skb->nh.arph->ar_sip, skb->phy.ethh->h_source, ARP_ESTABLISHED);
				break;
		}
		DBGPRINT(DBG_LEVEL_TRACE,"<==arp_input\n");
	EXITarp_input:
		return 0;
}
