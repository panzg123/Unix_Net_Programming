/*
 * sip_skbuff.c
 *
 *  Created on: 2015-6-1
 *      Author: panzg
 */
#include "sip.h"

struct skbuff *skb_alloc(__u32 size)
{
	DBGPRINT(DBG_LEVEL_MOMO,"==>skb_alloc\n");
	struct skbuff *skb = (struct skbuff*)malloc(sizeof(struct skbuff));	/*申请skbuff结构内存空间*/
	if(!skb)														/*失败*/
	{
		DBGPRINT(DBG_LEVEL_ERROR,"Malloc skb header error\n");
		goto EXITskb_alloc;										/*退出*/
	}
	memset(skb, 0, sizeof(struct skbuff));							/*初始化skbuff内存结构*/

	size = SKB_DATA_ALIGN(size);								/*按照系统设置对申请空间的大小进行规整化*/
	skb->head = (__u8*)malloc(size);								/*申请数据区域内存,并保存在head指针中*/
	if(!skb->head)												/*申请内存失败*/
	{
		DBGPRINT(DBG_LEVEL_ERROR,"Malloc skb data error\n");
		free(skb);												/*释放之前申请成功的skbuff结构内存*/
		goto EXITskb_alloc;										/*退出*/
	}
	memset(skb->head, 0, size);									/*初始化用户内存区*/

	skb->end = skb->head + size;									/*end指针位置初始化*/
	skb->data = skb->head;										/*data指针初始化为和head一致*/
	skb->tail = skb->data;											/*tail最初和data一致*/
	skb->next = NULL;												/*next初始化为空*/
	skb->tot_len = 0;												/*有用数据总长度为0*/
	skb->len = 0;													/*当前结构中的数据长度为0*/
	DBGPRINT(DBG_LEVEL_MOMO,"<==skb_alloc\n");
	return skb;													/*返回成功的指针*/
EXITskb_alloc:
	return NULL;													/*错误,返回空*/
}

void skb_free(struct skbuff *skb)
{
	if(skb)														/*判断结构是否为空*/
	{
		if(skb->head)											/*判断是否有用户空间*/
			free(skb->head);										/*释放用户空间内存*/
		free(skb);												/*释放skb结构内存空间*/
	}
}
void skb_clone(struct skbuff *from, struct skbuff *to)
{
	memcpy(to->head, from->head, from->end - from->head);		/*拷贝用户数据*/
	to->phy.ethh = (struct sip_ethhdr*)skb_put(to, ETH_HLEN);			/*更改目的结构以太网的指针位置*/
	to->nh.iph = (struct sip_iphdr*)skb_put(to, IPHDR_LEN);			/*更改IP头部的指针位置*/
}


__u8 *skb_put(struct skbuff *skb, __u32 len)
{
	DBGPRINT(DBG_LEVEL_MOMO,"==>skb_put\n");
	__u8 *tmp = skb->tail;										/*保存尾部指针位置*/
	skb->tail += len;												/*移动尾部指针*/
	skb->len  -= len;												/*长度当前网络数据长度减少*/
	//skb->tot_len += len;

	DBGPRINT(DBG_LEVEL_MOMO,"<==skb_put\n");
	return tmp;													/*返回尾部指针位置*/
}

#if 0
/* CRC16校验和计算icmp_cksum
参数：
	data:数据
	len:数据长度
返回值：
	计算结果，short类型
*/
unsigned short cksum(__u8 *data,  int len)
{
       int sum=0;/* 计算结果 */
	int odd = len & 0x01;/*是否为奇数*/

	unsigned short *value = (unsigned short*)data;
	/*将数据按照2字节为单位累加起来*/
       while( len & 0xfffe)  {
              sum += *(unsigned short*)data;
		data += 2;
		len -=2;
       }
	/*判断是否为奇数个数据，若ICMP报头为奇数个字节，会剩下最后一字节。*/
       if( odd) {
		unsigned short tmp = ((*data)<<8)&0xff00;
              sum += tmp;
       }
       sum = (sum >>16) + (sum & 0xffff);/* 高低位相加 */
       sum += (sum >>16) ;		/* 将溢出位加入 */

       return ~sum; /* 返回取反值 */
}
#else
static __u16
SIP_ChksumStandard(void *dataptr, __u16 len)
{
  __u32 acc;
  __u16 src;
  __u8 *octetptr;

  acc = 0;
  /* dataptr may be at odd or even addresses */
  octetptr = (__u8*)dataptr;
  while (len > 1)
  {
    /* declare first octet as most significant
       thus assume network order, ignoring host order */
    src = (*octetptr) << 8;
    octetptr++;
    /* declare second octet as least significant */
    src |= (*octetptr);
    octetptr++;
    acc += src;
    len -= 2;
  }
  if (len > 0)
  {
    /* accumulate remaining octet */
    src = (*octetptr) << 8;
    acc += src;
  }
  /* add deferred carry bits */
  acc = (acc >> 16) + (acc & 0x0000ffffUL);
  if ((acc & 0xffff0000) != 0) {
    acc = (acc >> 16) + (acc & 0x0000ffffUL);
  }
  /* This maybe a little confusing: reorder sum using htons()
     instead of ntohs() since it has a little less call overhead.
     The caller must invert bits for Internet sum ! */
  return htons((__u16)acc);
}

__u16 SIP_Chksum(void *dataptr, __u16 len)
{
	__u32 acc;

	acc = SIP_ChksumStandard(dataptr, len);
	while ((acc >> 16) != 0)
	{
		acc = (acc & 0xffff) + (acc >> 16);
	}

	return (__u16)~(acc & 0xffff);
}
#endif



/* inet_chksum_pseudo:
 *
 * Calculates the pseudo Internet checksum used by TCP and UDP for a pbuf chain.
 * IP addresses are expected to be in network byte order.
 *
 * @param p chain of pbufs over that a checksum should be calculated (ip data part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo header)
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
__u16
SIP_ChksumPseudo(struct skbuff *skb,
       struct in_addr *src, struct in_addr *dest,
       __u8 proto, __u16 proto_len)
{
	__u32 acc;
	__u8 swapped;

	acc = 0;
	swapped = 0;
	{
		acc += SIP_Chksum(skb->data, skb->end - skb->data);
		while ((acc >> 16) != 0)
		{
			acc = (acc & 0xffffUL) + (acc >> 16);
		}
		if (skb->len % 2 != 0)
		{
			swapped = 1 - swapped;
			acc = ((acc & 0xff) << 8) | ((acc & 0xff00UL) >> 8);
		}
	}

	if (swapped)
	{
		acc = ((acc & 0xff) << 8) | ((acc & 0xff00UL) >> 8);
	}

	/*为头部校验和*/
	acc += (src->s_addr & 0xffffUL);
	acc += ((src->s_addr >> 16) & 0xffffUL);
	acc += (dest->s_addr & 0xffffUL);
	acc += ((dest->s_addr >> 16) & 0xffffUL);
	acc += (__u32)htons((__u16)proto);
	acc += (__u32)htons(proto_len);

	while ((acc >> 16) != 0)
	{
		acc = (acc & 0xffffUL) + (acc >> 16);
	}

	return (__u16)~(acc & 0xffffUL);
}
