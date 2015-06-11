/*
 * sip_ip.c
 *
 *  Created on: 2015-6-2
 *      Author: panzg
 */

#include"sip.h"

/*
 * 对IP地址合法性进行判断
 */
inline int IP_IS_BROADCAST(struct net_device *dev,__be32 ip)
{
	int retval = 1;
	if((ip == IP_ADDR_ANY_VALUE) 						/*IP地址为本地任意IP地址*/
			||(~ip == IP_ADDR_ANY_VALUE))				/*或者为按位取反IP地址*/
		{
			DBGPRINT(DBG_LEVEL_NOTES, "IP is ANY ip\n");
			retval = 1;									/*是广播地址*/
			goto EXITin_addr_isbroadcast;					/*退出*/
		}else if(ip == dev->ip_host.s_addr)	{				/*IP地址为本地地址*/
			DBGPRINT(DBG_LEVEL_NOTES, "IP is local ip\n");
			retval = 0;									/*不是广播地址*/
			goto EXITin_addr_isbroadcast;					/*退出*/
		}else if(((ip&dev->ip_netmask.s_addr) 				/*IP地址为本子网内地址*/
						== (dev->ip_host.s_addr &dev->ip_netmask.s_addr))
			&& ((ip & ~dev->ip_netmask.s_addr) 			/*与广播地址同网段*/
						==(IP_ADDR_BROADCAST_VALUE & ~dev->ip_netmask.s_addr))){
			DBGPRINT(DBG_LEVEL_NOTES, "IP is ANY ip\n");
			retval =1;									/*是广播地址*/
			goto EXITin_addr_isbroadcast;					/*退出*/
		}else{											/*不是广播IP地址*/
			retval = 0;
		}
	EXITin_addr_isbroadcast:
		return retval;
}

/*该宏函数用于释放重组队列*/
#define IP_FREE_REASS(ipr) \
do{ \
	struct skbuff *skb =NULL,*skb_prev=NULL;\
	for(skb_prev = skb = ipr->skb; 			\
		skb != NULL; 						\
		skb_prev = skb, 					\
		skb = skb->next,					\
		skb_free(skb_prev));				\
		free(ipr);						\
}while(0)


#define IPREASS_TIMEOUT 3  	/*IP分组重组的超时时间为3秒*/
static struct sip_reass *ip_reass_list = NULL;				/*IP重组的链表*/

/*
 * 数据包重组函数
 */
struct skbuff *sip_reassemble(struct skbuff* skb)
{
	struct sip_iphdr *fraghdr = skb->nh.iph;
	int retval = 0;
	__u16 offset, len;
	int found = 0;

	offset = (fraghdr->frag_off & 0x1FFF)<<3;				/*取得IP分组偏移地址,32位长*/
	len = fraghdr->tot_len - fraghdr->ihl<<2;				/*IP分组的数据长度*/

	struct sip_reass *ipr = NULL,*ipr_prev = NULL;
	for(ipr_prev = ipr= ip_reass_list; ipr != NULL;	)
	{
		if(time(NULL) -ipr->timer > IPREASS_TIMEOUT)	/*此分组是超时?*/
		{
			if(ipr_prev == NULL)						/*第一个分片?*/
			{
				ipr_prev = ipr;						/*更新守护的指针为本分组*/
				ip_reass_list->next = ipr = ipr->next;	/*将超时的分片从重组链表上取下来*/
				ipr = ipr->next;						/*更新当前的分组指针*/
				IP_FREE_REASS(ipr_prev);				/*释放资源*/
				ipr_prev->next =NULL;					/*重置指针为空*/

				continue;							/*继续查找合适的分组*/
			}
			else										/*不是第一个分组*/
			{
				ipr_prev->next = ipr->next;				/*从分片链表上摘除当前链*/
				IP_FREE_REASS(ipr);					/*释放当前重组链*/
				ipr = ipr_prev->next;					/*更新当前链的指针*/
				continue;							/*继续查找*/
			}
		}

		/*分片是否输入此条链*/
		if(ipr->iphdr.daddr == fraghdr->daddr 			/*目的IP地址匹配*/
			&&ipr->iphdr.saddr == fraghdr->saddr		/*源IP地址匹配*/
			&&ipr->iphdr.id == fraghdr->id)				/*分片的ID匹配*/
		{
			found = 1;								/*属于这条链*/
			break;
		}
	}

	if(!found)										/*没有找到合适的分组链?*/
	{
		ipr_prev = NULL;								/*初始化为空*/
		ipr = (struct sip_reass*)malloc(sizeof(struct sip_reass));/*申请一个分组数据结构*/
		if(!ipr)										/*申请失败*/
		{
			retval = -1;								/*返回值-1*/
			goto freeskb;							/*退出*/
		}

		memset(ipr, 0, sizeof(struct sip_reass));			/*初始化分组结构*/

		ipr->next = ip_reass_list;						/*将当前分组结构挂接到分组链的头部*/
		ip_reass_list = ipr;

		memcpy(&ipr->iphdr, skb->nh.raw, sizeof(IPHDR_LEN));/*拷贝IP的数据头部,便于之后的分片匹配*/
	}else{											/*找到合适的分组链*/
		if(((fraghdr->frag_off & 0x1FFF) == 0)			/*当前数据位于分片第一个*/
			&&((ipr->iphdr.frag_off & 0x1FFF) != 0))		/*分组链上的头部不是第一个分片*/
		{
			memcpy(&ipr->iphdr, fraghdr, IPHDR_LEN);	/*更新重组中的IP头部结构*/
		}
	}

	/* 检查是否为最后一个分组*/
	if( (fraghdr->frag_off & htons(0x2000)) == 0) {		/*没有更多分组*/
		#define IP_REASS_FLAG_LASTFRAG 0x01

	  	ipr->flags |= IP_REASS_FLAG_LASTFRAG;			/*设置最后分组标志*/
		ipr->datagram_len = offset + len;				/*设置IP数据报文的全长*/
  	}


	/*将当前的数据放到重组链上,并更新状态*/
	struct skbuff *skb_prev=NULL, *skb_cur=NULL;
	int finish =0;
	void *pos = NULL;
	__u32 length = 0;
#define FRAG_OFFSET(iph) (ntohs(iph->frag_off & 0x1FFF)<<3)
#define FRAG_LENGTH(iph) (ntohs(iph->tot_len) - IPHDR_LEN)
	for(skb_prev =NULL, skb_cur=ipr->skb,length = 0,found = 0;
		skb_cur != NULL && !found;
		skb_prev=skb_cur,skb_cur = skb_cur->next)
	{
		if(skb_prev !=NULL)									/*不是第一个分片*/
		{
			if((offset  < FRAG_OFFSET(skb_cur->nh.iph))			/*接收数据的偏移值位于前后两个之间*/
				&&(offset > FRAG_OFFSET(skb_prev->nh.iph)))
			{
				skb->next = skb_cur;							/*将接收到的数据放到此位置*/
				skb_prev->next = skb;

				if(offset + len > FRAG_OFFSET(skb_cur->nh.iph))	/*当前数据与后面的分片数据覆盖?*/
				{
					__u16 modify = FRAG_OFFSET(skb_cur->nh.iph) - offset + IPHDR_LEN;/*计算当前链的数据长度修改值*/
					skb->nh.iph->tot_len = htons(modify);		/*更新当前链长度*/
				}

				if(FRAG_OFFSET(skb_prev->nh.iph) 				/*前面的分片长度覆盖当前数据?*/
					+ FRAG_LENGTH(skb_prev->nh.iph)
						> FRAG_OFFSET(skb_cur->nh.iph))
				{
					__u16 modify = FRAG_OFFSET(skb_prev->nh.iph) - offset + IPHDR_LEN;/*计算前面数据长度的更改之*/
					skb_prev->nh.iph->tot_len = htons(modify);	/*修改前一片的数据长度*/
				}

				found = 1;									/*找到合适的分片插入位置*/
			}
		}
		else													/*为重组链上的头部*/
		{
			if(offset  < FRAG_OFFSET(skb_cur->nh.iph)){			/*当前链的偏移量小于第一个分片的偏移长度*/
				skb->next = ipr->skb;							/*挂接到重组链的头部*/
				ipr->skb = skb;
				if(offset + len + IPHDR_LEN 						/*查看是否覆盖后面分片的数据*/
					> FRAG_OFFSET(skb_cur->nh.iph))
					{
					__u16 modify = FRAG_OFFSET(skb_cur->nh.iph) - offset + IPHDR_LEN;/*修改分片的数据长度*/
					if(!offset)								/*偏离量为0*/
						modify -= IPHDR_LEN;					/*包含头部,所以数据段长度需要减去IP头部长度*/

					skb->nh.iph->tot_len = htons(modify);		/*设置分片中修改后的长度*/
				}
			}
		}

		length += skb_cur->nh.iph->tot_len - IPHDR_LEN;			/*当前链表中的数据长度*/
	}

	/*重新计算重组链上的总数据长度*/
	for(skb_cur=ipr->skb,length = 0;
		skb_cur != NULL;
		skb_cur = skb_cur->next)
	{
		length += skb_cur->nh.iph->tot_len - IPHDR_LEN;
	}
	length += IPHDR_LEN;

	/*全部的IP分片都已经接收到后进行数据报文的重新组合
	数据拷贝到一个新的数据结构中，原来的数据接收都释放掉
	并从分组链中取出，将重组后的数据结构指针返回*/
	if(length == ipr->datagram_len )							/*分组全部接收到?*/
	{
		ipr->datagram_len += IPHDR_LEN;					/*计算数据报文的实际长度长度*/
		skb = skb_alloc(ipr->datagram_len + ETH_HLEN);		/*申请空间*/

		skb->phy.raw = skb_put(skb, ETH_HLEN);			/*物理层*/
		skb->nh.raw = skb_put(skb, IPHDR_LEN);			/*网络层*/
		memcpy(skb->nh.raw, & ipr->iphdr, sizeof(ipr->iphdr));	/*向新数据结构中拷贝IP头*/
		skb->nh.iph->tot_len = htons(ipr->datagram_len);		/*新结构中的tot_len*/

		for(skb_prev=skb_cur=ipr->skb;skb_cur != NULL;)		/*遍历重组数据链*/
		{
			int size = skb_cur->end - skb_cur->tail;			/*计算拷贝数据源的长度*/
			pos = skb_put(skb, size);						/*计算拷贝目的地址位置*/
			memcpy(pos, 									/*将一个分片拷贝到新结构中*/
				skb_cur->tail,
				skb_cur->nh.iph->tot_len - skb_cur->nh.iph->ihl<<2);
		}

		/*一下从重组链中摘除数据并释放,然后设置新结构中的几个IP头部参数*/
		ipr_prev->next = ipr->next;							/*将此数据报文从重组链中摘除*/
		IP_FREE_REASS(ipr);								/*释放此报文的重组连*/
		skb->nh.iph->check = 0;							/*设置校验值为0*/
		skb->nh.iph->frag_off = 0;							/*偏移值为0*/
		skb->nh.iph->check = SIP_Chksum(skb->nh.raw, skb->nh.iph->tot_len);/*计算IP头部校验和*/
	}

normal:
	return skb;
freeskb:
	skb_free(skb);
	return NULL;
}

/*
 * 数据分片函数
 */
struct skbuff* ip_frag(struct net_device *dev,struct skbuff*skb)
{
	__u8 frag_num = 0;
		__u16 tot_len = ntohs(skb->nh.iph->tot_len);
		__u8 mtu = dev->mtu;
		__u8 half_mtu = (mtu+1)/2;
		frag_num = (tot_len - IPHDR_LEN + half_mtu)/(mtu - IPHDR_LEN - ETH_HLEN);/*计算分片的个数*/

		__u16 i = 0;
		struct skbuff *skb_h = NULL,*skb_t = NULL,*skb_c = NULL;
		for(i = 0,skb->tail = skb->head; i<frag_num;i++)
		{
			if(i ==0){													/*第一个分片*/
				skb_t = skb_alloc(mtu);									/*申请内存*/
				skb_t->phy.raw = skb_put(skb_t, ETH_HLEN);					/*物理层*/
				skb_t->nh.raw = skb_put(skb_t, IPHDR_LEN);					/*网络层*/

				memcpy(skb_t->head, skb->head, mtu);						/*拷贝数据*/
				skb_put(skb,mtu);										/*增加数据长度len值*/
				skb_t->nh.iph->frag_off = htons(0x2000);						/*设置偏移标记值*/
				skb_t->nh.iph->tot_len = htons(mtu-ETH_HLEN);				/*设置IP头部总长度*/
				skb_t->nh.iph->check = 0;									/*设置校验和为0*/
				skb_t->nh.iph->check = SIP_Chksum(skb_t->nh.raw, IPHDR_LEN);/*计算校验和*/

				skb_h = skb_c =skb_t;										/*头部分片指针设置*/
			}else if(i==frag_num -1){										/*最后一个分片*/
				skb_t = skb_alloc(mtu);									/*申请内存*/
				skb_t->phy.raw = skb_put(skb_t, ETH_HLEN);					/*物理层*/
				skb_t->nh.raw = skb_put(skb_t, IPHDR_LEN);					/*网络层*/

				memcpy(skb_t->head, skb->head, ETH_HLEN + IPHDR_LEN);		/*拷贝数据*/
				memcpy(skb_t->head + ETH_HLEN + IPHDR_LEN, skb->tail, skb->end - skb->tail);/*增加数据长度len值*/
				skb_t->nh.iph->frag_off = htons(i*(mtu - ETH_HLEN - IPHDR_LEN) + IPHDR_LEN);/*设置偏移标记值*/
				skb_t->nh.iph->tot_len = htons(skb->end - skb->tail + IPHDR_LEN);/*设置IP头部总长度*/
				skb_t->nh.iph->check = 0;									/*设置校验和为0*/
				skb_t->nh.iph->check = SIP_Chksum(skb_t->nh.raw, IPHDR_LEN);/*计算校验和*/

				skb_c->next=skb_t;										/*挂接此分片*/
			}else{
				skb_t = skb_alloc(mtu);
				skb_t->phy.raw = skb_put(skb_t, ETH_HLEN);
				skb_t->nh.raw = skb_put(skb_t, IPHDR_LEN);

				memcpy(skb_t->head, skb->head, ETH_HLEN + IPHDR_LEN);
				memcpy(skb_t->head + ETH_HLEN + IPHDR_LEN, skb->tail, mtu - ETH_HLEN - IPHDR_LEN);
				skb_put(skb_t, mtu - ETH_HLEN - IPHDR_LEN);
				skb_t->nh.iph->frag_off = htons((i*(mtu - ETH_HLEN - IPHDR_LEN) + IPHDR_LEN)|0x2000);
				skb_t->nh.iph->tot_len = htons(mtu - ETH_HLEN);
				skb_t->nh.iph->check = 0;
				skb_t->nh.iph->check = SIP_Chksum(skb_t->nh.raw, IPHDR_LEN);

				skb_c->next=skb_t;
				skb_c = skb_t;
			}
			skb_t->ip_summed = 1;										/*已经进行了IP校验和计算*/
		}

		skb_free(skb);													/*释放原来的网络数据*/
		return skb_h;													/*返回分片的头部指针*/

}
/*
 * 功能：接受数据
 * 判断数据是否合法，交给上层ICMP或者UDP，目前只支持这两种协议数据
 */
int ip_input(struct net_device *dev,struct skbuff *skb)
{
	DBGPRINT(DBG_LEVEL_TRACE,"==>ip_input\n");
		struct sip_iphdr *iph = skb->nh.iph;
		int retval = 0;

		if(skb->len<0)  /*网络数据长度不合法*/
		{
			skb_free(skb);
			retval=-1;
			goto EXITip_input;
		}
		if(iph->version != 4)								/*IP版本不合适,不是IPv4*/
		{
			skb_free(skb);
			retval = -1;
			goto EXITip_input;
		}

		__u16 hlen = iph->ihl<<2;							/*计算IP头部长度*/
		if(hlen < IPHDR_LEN)								/*长度国小*/
		{
			skb_free(skb);
			retval = -1;
			goto EXITip_input;
		}

		if(skb->tot_len - ETH_HLEN < ntohs(iph->tot_len))		/*计算总长度是否合法*/
		{
			skb_free(skb);
			retval = -1;
			goto EXITip_input;
		}


		if(hlen < ntohs(iph->tot_len))						/*头部长度是否合法*/
		{
			skb_free(skb);
			retval = -1;
			goto EXITip_input;
		}

		if(SIP_Chksum(skb->nh.raw, IPHDR_LEN))			/*计算IP头部的校验和,是否正确,为0*/
		{
			DBGPRINT(DBG_LEVEL_ERROR, "IP check sum error\n");
			skb_free(skb);
			retval= -1;
			goto EXITip_input;
		}
		else												/*校验和合法*/
		{
			skb->ip_summed = CHECKSUM_HW;				/*设置IP校验标记*/
			DBGPRINT(DBG_LEVEL_NOTES, "IP check sum success\n");
		}

		if((iph->daddr != dev->ip_host.s_addr 			/*不是发往本地*/
			&& !IP_IS_BROADCAST(dev, iph->daddr)		/*目的地址不是广播地址*/
			||IP_IS_BROADCAST(dev, iph->saddr)))		/*源地址不是广播地址*/
		{
			DBGPRINT(DBG_LEVEL_NOTES, "IP address INVALID\n");
			skb_free( skb);
			retval= -1;
			goto EXITip_input;
		}

		if((ntohs(iph->frag_off) & 0x3FFF) !=0)				/*有偏移,是一个分片*/
		{
			skb = sip_reassemble(skb);					/*进行分片重组*/
			if(!skb){									/*重组不成功*/
				retval = 0;
				goto EXITip_input;
			}
		}

		switch(iph->protocol)								/*IP协议类型*/
		{
			case IPPROTO_ICMP:							/*ICMP协议*/
				skb->th.icmph = 							/*ICMP头部指针获取*/
					(struct sip_icmphdr*)skb_put(skb, sizeof(struct sip_icmphdr));
				icmp_input(dev, skb);					/*转给ICMP模块处理*/
				break;
			case IPPROTO_UDP:							/*UDP协议*/
				skb->th.udph = 							/*UDP头部指针获取*/
					(struct sip_udphdr*)skb_put(skb, sizeof(struct sip_udphdr));
				SIP_UDPInput(dev, skb);					/*转给UDP模块处理*/
				break;
			default:
				break;
		}
		EXITip_input:
		    DBGPRINT(DBG_LEVEL_TRACE,"<==ip_input\n");
			return retval;
}
/*
 * 功能：输出数据
 * 填充IP头部，计算校验和，可能进行分片，最后调用网络层output发送。
 */
int ip_output(struct net_device *dev,struct skbuff *skb,
		struct in_addr *src,struct in_addr *dest,
		__u8 ttl,__u8 tos,__u8 proto)
{
	struct sip_iphdr* iph = skb->nh.iph;     /*获取IP头部指针*/
	iph->protocol = proto;
	iph->tos = tos;
	iph->ttl = ttl;
	iph->daddr = dest->s_addr;						/*设置目的IP地址*/
	iph->saddr = src->s_addr;							/*设置源IP地址*/

	iph->check = 0;									/*校验和初始化为0*/
	iph->check = (SIP_Chksum(skb->nh.raw, sizeof(struct sip_iphdr)));/*IP头部校验和计算*/
	if(SIP_Chksum(skb->nh.raw, sizeof(struct sip_iphdr)))/**/
	{
		DBGPRINT(DBG_LEVEL_ERROR, "ICMP check IP sum error\n");
	}
	else
	{
		DBGPRINT(DBG_LEVEL_NOTES, "ICMP check IP sum success\n");
	}

	if(skb->len > dev->mtu){							/*如果网络数据超过以太网的MTU*/
		skb= ip_frag(dev, skb);						/*进行分片*/
	}

	dev->output( skb,dev);							/*通过以太网的输出函数发送数据*/
}

