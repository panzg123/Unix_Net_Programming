#ifndef __KERNEL__
#define __KERNEL__
#endif /*__KERNEL__*/
#ifndef MODULE
#define MODULE
#endif /*MODULE*/
#include "sipfw.h"


/* 根据秒数获得本地 日期的简单程序
*	本程序是用查表的方法来计算
*	2007年到2012年的时间
* 参数:
*	r:时间结构，用于将计算结果传出
*/
void SIPFW_Localtime(struct tm *r, unsigned long time)
{
	unsigned int year, i, days, sec;
	__u16 *yday = NULL;
	/* 2007年到2012年与1970年的天数 */
	__u16 days_since_epoch[] = 
	{
		/* 2007 - 2012 */
		13514,13879, 14245, 14610,14975, 15340, 
	};

	/*某月在一年中开始的天数*/
	__u16 days_since_year[] = {
		0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334,
	};
	/*某月在一个润年中开始的天数*/
	__u16 days_since_leapyear[] = {
		0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335,
	};
	yday = days_since_year;				/*假设为一般年*/

	sec = time + 3600*8;					/*加上东八区的秒数*/
	days = sec /(3600*24);					/*整天数*/
	sec =  sec % (3600*24);				/*一天内秒数*/
	r->hour = sec / 3600;					/*小时数*/
	sec = sec % 3600;						/*一小时内秒数*/
	r->min = sec / 60;					/*分钟数*/
	r->sec = sec % 60;					/*一分钟内秒数*/

	/*查表计算1970开始的年数*/
	for(i= 0, year = 2007; days_since_epoch[i]<days; i++,year++)
		;
	year--;i--;							/*回复正确的数值*/
	
	days -= days_since_epoch[i];			/*年内天数*/
	
	if (year% 4 == 0 && (year % 100 != 0 || year % 400 == 0)) 
	{
		yday = days_since_leapyear;		/*闰年*/
	}
	

	for (i=0; i < 12 && days > yday[i]; i++)	/*查找月份*/
		;
	r->year = year;						/*年数*/
	r->mon    = i ;						/*月数*/
	r->mday = days -yday[i-1];			/*月中日期*/
	
	return ;
}

/*判断网络数据和规则的附加项是否匹配，
*	包含端口号、TCP的标志位、ICMP/IGMP类型代码
* 参数:
*	iph为IP头部指针
*	data为IP的负载
*	r为规则
*/
static int SIPFW_IsAddtionMatch(struct iphdr *iph,  void *data, struct sipfw_rules *r)
{
	int found = 0;

	DBGPRINT("==>SIPFW_IsAddtionMatch\n");

	switch(iph->protocol)
	{
		case IPPROTO_TCP:/*TCP协议中判断端口和标志位*/
		{
			struct tcphdr *tcph = (struct tcphdr *)data;
			if( (tcph->source == r->sport || r->sport == 0)/*端口*/
				&&(tcph->dest == r->dport || r->dport == 0))
			{
				if(!r->addtion.valid)/*规则中不存在标志位*/
				{
					found = 1;/*匹配*/
				}
				else	/*存在标志位*/
				{
					/*判断TCP头部的标志位*/
					struct tcp_flag *tcpf = &r->addtion.tcp;
					if(tcpf->ack == tcph->ack		/*ACK/SYN*/
						&&tcpf->fin == tcph->fin	/*FIN*/
						&&tcpf->syn == tcph->syn)	/*SYN*/
					{
						found = 1;/*匹配*/
					}
				}
			}
		}
		break;
		
		case IPPROTO_UDP:/*UDP协议判断端口*/
		{
			struct tcphdr *udph = (struct tcphdr *)data;
			if( (udph->source == r->sport || r->sport == 0)
				&&(udph->dest == r->dport || r->dport == 0))
			{
				found = 1;
			}
		}
		break;
		
		case IPPROTO_ICMP:/*ICMP判断类型和代码*/		
		case IPPROTO_IGMP:/*IGMP判断类型和代码*/
		{
			struct igmphdr *igmph = (struct igmphdr*)data;
			if(!r->addtion.valid)/*不存在类型*/
			{
				found = 1;
			}
			else/*存在类型*/
			{
				struct icgmp_flag *impf = &r->addtion.icgmp;
				if(impf->type == igmph->type && impf->code == igmph->code)
				{
					found = 1;/*符合*/
				}
			}
		}
		break;
		
		default:/*其他不符合*/
			found = 0;
			break;
	}

	DBGPRINT("==>SIPFW_IsAddtionMatch\n");

	return found;
}

/*匹配网络数据和规则中的IP地址及协议是否匹配*/
static int SIPFW_IsIPMatch(struct iphdr *iph, struct sipfw_rules *r)
{
	int found = 0;
	DBGPRINT("==>SIPFW_IsIPMatch\n");
	if((iph->daddr == r->dest|| r->dest == 0)/*目的地址*/
		&&(iph->saddr==r->source|| r->source == 0)/*源地址*/
		&&( iph->protocol== r->protocol  ||  r->protocol == 0))/*协议*/
	{
		found = 1;/*匹配*/
	}

	DBGPRINT("<==SIPFW_IsIPMatch\n");
	return found;
}

/*判断网络数据和一条链上的规则是否匹配*/
struct sipfw_rules * SIPFW_IsMatch(struct sk_buff *skb,struct sipfw_rules *l)
{
	struct sipfw_rules *r = NULL;	/*规则*/
	struct iphdr *iph = NULL;		/*IP头部*/
	void *p = NULL;				/*网络数据负载*/
	int found = 0;				/*是否匹配*/

	

	iph = skb->nh.iph;			/*找到IP头部*/

	p = skb->data + skb->nh.iph->ihl*4;/*负载部分*/

	DBGPRINT("source IP:%x,dest:%x\n",iph->saddr,iph->daddr);
	if(l == NULL)					/*链为空直接退出*/
	{
		goto EXITSIPFW_IsMatch;
	}
	for(r = l; r != NULL; r = r->next)/*在链上循环匹配规则*/
	{
		if(SIPFW_IsIPMatch(iph, r))/*IP是否匹配*/
		{
			if(SIPFW_IsAddtionMatch(iph,p,r))/*附加数据是否匹配*/
			{
				found = 1;/*匹配*/
				break;
			}
		}
	}
	
EXITSIPFW_IsMatch:	
	return found?r:NULL;
}

/*销毁规则链表，释放资源*/
int SIPFW_ListDestroy(void)
{
	struct sipfw_list *l = NULL;
	struct sipfw_rules *prev = NULL;
	struct sipfw_rules *cur = NULL;
	int i ;
	DBGPRINT("==>SIPFW_ListDestroy\n");

	for(i = 0;i < 3; i++)/*遍历三个链*/
	{
		
		l = &sipfw_tables[i];
		for(cur = l->rule; 		/*遍历一个链*/
			cur != NULL; 
			prev = cur, cur = cur->next)
		{
			if(prev)	/*释放内存*/
			{
				kfree(prev);
			}
		}
		l->rule = NULL;/*清理指针*/
		l->number = 0;/*清理链表内规则个数*/
	}

	DBGPRINT("<==SIPFW_ListDestroy\n");
	return 0;
}



