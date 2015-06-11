#if 0
#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <asm/semaphore.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "sipfw.h"

DECLARE_MUTEX(receive_sem);

static struct sock *nlfd;

struct
{
  	__u32 pid;
  	rwlock_t lock;
}user_proc;

static void kernel_receive(struct sock *sk, int len)
{
	do{
		struct sk_buff *skb;
		if(down_trylock(&receive_sem))
			return;
		while((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL)
		{
			struct nlmsghdr *nlh = NULL;
			if(skb->len >= sizeof(struct nlmsghdr))
			{
				nlh = (struct nlmsghdr *)skb->data;
				if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
					&& (skb->len >= nlh->nlmsg_len))
				{
					if(nlh->nlmsg_type == SIPFW_U_PID)
					{
						write_lock_bh(&user_proc.lock);
						user_proc.pid = nlh->nlmsg_pid;
						write_unlock_bh(&user_proc.lock);
					}
					else if(nlh->nlmsg_type == SIPFW_CLOSE)
					{
						write_lock_bh(&user_proc.lock);
						if(nlh->nlmsg_pid == user_proc.pid)
							user_proc.pid = 0;
						write_unlock_bh(&user_proc.lock);
					}
				}
			}
			kfree_skb(skb);
		}
		up(&receive_sem);
	}while(nlfd && nlfd->sk_receive_queue.qlen);
}

static int send_to_user(struct packet_info *info)
{
	int ret;
	int size;
	unsigned char *old_tail;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct packet_info *packet;

	size = NLMSG_SPACE(sizeof(*info));

	skb = alloc_skb(size, GFP_ATOMIC);
	old_tail = skb->tail;

	nlh = NLMSG_PUT(skb, 0, 0, SIPFW_K_MSG, size-sizeof(*nlh));
	packet = NLMSG_DATA(nlh);
	memset(packet, 0, sizeof(struct packet_info));

	packet->src = info->src;
	packet->dest = info->dest;

	nlh->nlmsg_len = skb->tail - old_tail;
	NETLINK_CB(skb).dst_group = 0;

	read_lock_bh(&user_proc.lock);
	ret = netlink_unicast(nlfd, skb, user_proc.pid, MSG_DONTWAIT);
	read_unlock_bh(&user_proc.lock);

	return ret;

 nlmsg_failure:
 	if(skb)
		kfree_skb(skb);

	return -1;
}
#if 0
struct sipfw_rules;
struct sipfw_list;

struct sipfw_rules{
	__u8	chain;
	__be32	saddr;
	__be32	daddr;

	__be16	sport;
	__be16	dport;
	__u8	protocol;
	int		policy;
	__u8	ifname[5];
	union addtion
	{
		__u32 		value;
		struct icmp_flag
		{
			__u8	valid;
			__u8	type;
			__u8	code;
		}icmp;

		struct tcp_flag
		{
			__u8	valid;
			__u8 	flag;
		}tcp;

		struct igmp_flag
		{
			__u8	valid;
			__u8	type;
			__u8	code;
		}igmp;
	}addtion;
	struct sipfw_rules* next;
};
#endif
/*【#|目标链 动作 源IP 源端口 目的IP 目的端口 协议类型 网络接口】*/
pack_rule(struct sipfw_rules *rule, char *buff, int chain)
{

	sprintf(buff, 
		"%s "							/*目标链*/
		"%s "							/*动作*/
		"%d.%d.%d.%d "					/*源IP*/
		"%d "							/*源端口*/
		"%d.%d.%d.%d "					/*目的IP*/
		"%d "							/*目的端口*/
		"%d "							/*协议类型*/
		"%s "							/*网络接口*/
		chain_name[chain].ptr,			/*目标链*/
		action_name[rule->policy].ptr,	/*动作*/
		(rule->saddr&0xFF000000)>>24,	/*源IP第1段*/
		(rule->saddr&0x00FF0000)>>16,	/*源IP第2段*/
		(rule->saddr&0x0000FF00)>>8,		/*源IP第3段*/
		(rule->saddr&0x000000FF)>>0,		/*源IP第4段*/
		rule->sport,						/*源端口*/
		(rule->daddr&0xFF000000)>>24,	/*目的IP第1段*/
		(rule->daddr&0xFF000000)>>16,	/*目的IP第2段*/
		(rule->daddr&0xFF000000)>>8,		/*目的IP第3段*/
		(rule->daddr&0xFF000000)>>0,		/*目的IP第4段*/
		rule->dport,						/*目的端口*/
		rule->protocol,					/*协议类型*/
		rule->ifname						/*网络接口*/
	
		);
}
/*【#|目标链 动作 源IP 源端口 目的IP 目的端口 协议类型 网络接口】*/

strtol(char *str)
{
	int len = strlen(str);
	unsigned int ip = 0;
	int i = 0;
	for(i = 0; i < len; i++)
	{
		ip = ip*10 + *(str + i) - '0';
	}

	return ip;
}

inet_addr(char *str)
{
	unsigned int ip = 0;
	char *pos = str;
	char *p = str;
	int i = 0;
	for(;i<4;i++)
	{
		for(; pos != '.' && pos != '\0'; pos++) 
			;
		*pos = '\0';
		ip = ip<<8 + strtol(p)&0xFF;
		pos ++;
		p = pos;
	}

	return ip;
}

ReadRuleFile(struct file *f, struct sipfw_rules *rule )
{
	struct file *f = NULL;
	int len = 0;
	char buff[2048];
	struct sipfw_rules *rule = NULL;
	int count = 1;
	char *pos = NULL;
	int found = 0;
	struct sipfw_rules rule_inn;

	rule = &rule_inn;
	int i = 0;
	f = OpenFile(sipf.RuleFilePath, O_CREAT|O_WRONLY|O_APPEND, 0);

	count = ReadLine(f, buff, 2048);
	if(count <= 0 )
		return;

	char *line_end = count + buff;
	char *pos = buff;
	for( ;count > 0; count = ReadLine(f, buff, 2048),line_end=count + buff,pos = buff)
	{
		/*注释#*/
		if(*pos == '#')
		{
			continue;
		}

		/*目标链*/
		for(;i<3 && !found;i++)
		{
			if(!strncmp(pos, chain_name[i].ptr, chain_name[i].len))
			{
				rule.chain = i;
				pos += chain_name[i].len + 1;
				
				found = 1;
			}
		}
		
		/*动作*/
		for(i = 0, found = 0 ; i < 2 && !found; i++)
		{
			if(!strncmp(pos, action_name[i].ptr, chain_name[i].len))
			{
				rule.policy = i;
				pos += action_name[i].len + 1;
				found = 1;
			}
		}

		/*源IP */		
		for(i = 0; i<16; i++)
		{
			if(*(pos+i) == ' ')
			{
				*(pos+i) == '\0';
				break;
			}
		}
		rule->saddr = inet_addr(pos);
		pos += i + 1;
		
		/*源端口*/
		rule->sport = strtol(pos);
		for(;*pos != ' ';pos++)
			;
		pos++;
		
		/*目的IP */		
		for(i = 0; i<16; i++)
		{
			if(*(pos+i) == ' ')
			{
				*(pos+i) == '\0';
				break;
			}
		}
		rule->daddr = inet_addr(pos);
		pos += i + 1;
		
		/*目的端口*/
		rule->dport = strtol(pos);
		for(;*pos != ' ';pos++)
			;
		pos++;
		
		/*协议类型*/
		rule->protocol = strtol(pos);
		for(;*pos != ' ';pos++)
			;
		pos++;
		
		/*网络接口*/
		strcpy(rule->ifname, pos);

		rule = (struct sipfw_rules* )kmalloc(sizeof(struct sipfw_rules),GFP_KERNEL);
		memcpy(rule, &rule_inn, sizeof(rule_inn));
		rule->next = NULL;
		sipfw_table_add(rule, rule->chain);
		rule = &rule_inn;
	}
	CloseFile( f);
}

WriteRuleFile(void)
{
	struct file *f = NULL;
	int len = 0;
	char buff[2048];
	struct sipfw_rules *rule = NULL;
	int i = 0;

	f = OpenFile(sipf.RuleFilePath, O_CREAT|O_WRONLY|O_APPEND, 0);
	
	for(i = 0; i< 3; i++)
	{
		rule = &sipfw_tables[i];
		for( ;rule != NULL; rule= rule->next)
		{
			snprintf(buff, 
				     2048,
				     "%s "							/*目标链*/
				     "%s "							/*动作*/
				     "%d.%d.%d.%d "					/*源IP*/
				     "%d "							/*源端口*/
				     "%d.%d.%d.%d "					/*目的IP*/
				     "%d "							/*目的端口*/
				     "%d "							/*协议类型*/
				     "%s "							/*网络接口*/
				     chain_name[chain].ptr,			/*目标链*/
				     action_name[rule->policy].ptr,	/*动作*/
				     (rule->saddr&0xFF000000)>>24,	/*源IP第1段*/
				     (rule->saddr&0x00FF0000)>>16,	/*源IP第2段*/
				     (rule->saddr&0x0000FF00)>>8,		/*源IP第3段*/
				     (rule->saddr&0x000000FF)>>0,		/*源IP第4段*/
				     rule->sport,						/*源端口*/
				     (rule->daddr&0xFF000000)>>24,	/*目的IP第1段*/
				     (rule->daddr&0xFF000000)>>16,	/*目的IP第2段*/
				     (rule->daddr&0xFF000000)>>8,		/*目的IP第3段*/
				     (rule->daddr&0xFF000000)>>0,		/*目的IP第4段*/
				     rule->dport,						/*目的端口*/
				     rule->protocol,					/*协议类型*/
				     rule->ifname						/*网络接口*/);
			len = strlen(buff);
			WriteLine(f, buff,  len);
		}
	}
	CloseFile( f);
}


struct sipfw_list
{
	struct sipfw_rules		*rule;
	rwlock_t 				lock;
};
struct sipfw_list sipfw_tables[SIPFW_CHAIN_NUM] ;

/*
* 函数名: 
*	sipfw_table_init
* 功能:
*	初始化规则列表
* 返回值:
*	0成功，1失败
*/
static unsigned int sipfw_table_init(void)
{
	int i = 0;

	/* 申请三个链表的内存 */
	for(i = 0; i < SIPFW_CHAIN_NUM; i++)
	{
		sipfw_tables[i].rule = NULL;
	}	

	return 0;
}


/*
* 函数名: 
*	sipfw_table_destory
* 功能:
*	销毁规则列表
* 返回值:
*	0成功，1失败
*/
static unsigned int sipfw_table_destory(void)
{
	int i = 0;

	for(i =0; i< SIPFW_CHAIN_NUM; i++)
	{
		struct sipfw_rules *cur = NULL,*prev = NULL;
		read_lock_bh(&sipfw_tables[i].lock);
		for(cur = sipfw_tables[i].rule;
			cur != NULL; 
			prev = cur, cur=cur->next)
		{
			if(prev != NULL)
			{
				prev->next = NULL;
				kfree(prev);
				prev = NULL;
			}
		}
		read_unlock_bh(&sipfw_tables[i].lock);
	}

	return 0;
}

/*
* 函数名: 
*	sipfw_table_add
* 功能:
*	增加规则列表,新增加的规则位于链表的头部
*	如果当前链表中存在相同的规则，
*	在删除之前的相同规则后再增加规则
* 参数含义:
*	c:	增加的规则
*	chain:	规则链的枚举值
* 返回值:
*	0成功，1失败
*/
static unsigned int sipfw_table_add(struct sipfw_rules *c, int chain)
{
	struct sipfw_rules *l = NULL;

	/*先删除列表中相同的规则*/
	sipfw_table_delete(c,chain);

	/*增加新规则到列表首部*/	
	read_lock_bh(&sipfw_tables[chain].lock);	
	l = sipfw_tables[chain].rule;
	c->next = l;
	sipfw_tables[chain].rule = c;
	read_unlock_bh(&sipfw_tables[chain].lock);

	return 0;
}

/*
* 函数名: 
*	sipfw_table_delete
* 功能:
*	删除指定链中的相同规则
* 参数含义:
*	c:	要删除的规则
*	chain:	规则链的枚举值
* 返回值:
*	0成功，1失败
*/
static unsigned int sipfw_table_delete(struct sipfw_rules *c, int chain)
{
	struct sipfw_rules *prev =  NULL, *cur = NULL;
	int found = 0;

	read_lock_bh(&sipfw_tables[chain].lock);
	for(cur = sipfw_tables[chain].rule;  
		cur != NULL;  
		prev = cur, cur = cur->next)
	{
		if((cur->daddr == c->daddr)
			&&(cur->dport == c->dport)
			&&(cur->saddr==c->saddr)
			&&(cur->sport==c->sport)
			&&(cur->protocol== c->protocol)
			&&(cur->addtion.value == c->addtion.value))
		{
			if(prev == NULL)
			{
				sipfw_tables[chain].rule = NULL;
				kfree(cur);				
			}
			else
			{
				prev->next = cur->next;
				kfree(cur);
			}

			found = 1;
			break;
		}
	}
	read_unlock_bh(&sipfw_tables[chain].lock);

	return found?0:1;
}


static int sipfw_ismatch(struct sk_buff **pskb,struct sipfw_rules *l)
{
	struct sipfw_rules *c = NULL;
	struct sk_buff *skb = *pskb;
	char *p = NULL;
	int found = 0;
	__u32 saddr = 0;
	__u32 daddr =0;
	__u16 sport = 0;
	__u16 dport = 0;
	__u8   protocol = 0;

	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	iph = skb->nh.iph;
	saddr = iph->saddr;
	daddr = iph->daddr;
	protocol = iph->protocol;	

	p = skb->data + skb->nh.iph->ihl*4;
	switch(protocol)
	{
		case IPPROTO_TCP:
			printk("TCP protocol\n");
			tcph =  (struct tcphdr *)p;
			sport = tcph->source;
			dport = tcph->dest;
			break;
		case IPPROTO_UDP:
			printk("UDP protocol\n");
			udph =  (struct udphdr *)p;
			sport = udph->source;
			dport = udph->dest;
			break;
		case IPPROTO_ICMP:
			break;
		case IPPROTO_IGMP:
			break;
		default:
			break;
	}

	for(c = l; c != NULL; c = c->next)
	{
		if((daddr == c->daddr || c->daddr == 0)
			&&(dport == c->dport  || c->dport == 0)
			&&(saddr==c->saddr  || c->saddr == 0)
			&&(sport==c->sport  ||  c->sport == 0)
			&&(protocol== c->protocol  ||  c->protocol == 0))
		{
			printk("FOUND\n");
			found = 1;
			break;
		}
	}
	if(IPPROTO_TCP == protocol)
	printk("MATCHED is %d\n"
		"saddr:0x%x, 	daddr:0x%x,	sport:0x%x,	dport:0x%x, 	protocol:0x%x\n"
		"csaddr:0x%x, cdaddr:0x%x, csport:0x%x,	cdport:0x%x, 	cprotocol:0x%x\n",
		found,		
		saddr,			daddr,			sport,			dport,			protocol,		
		c->saddr,		c->daddr,		c->sport,			c->dport,		c->protocol);
	
	return found?c:NULL;
}

static unsigned int
sipfw_pre_routing_hook(unsigned int hook,
	struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = (*pskb)->nh.iph;
	struct packet_info info;

	if(iph->protocol == IPPROTO_ICMP)
	{
		read_lock_bh(&user_proc.lock);
		if(user_proc.pid != 0)
		{
			read_unlock_bh(&user_proc.lock);
			info.src = iph->saddr;
			info.dest = iph->daddr;
			send_to_user(&info);
		}
		else
		{
			read_unlock_bh(&user_proc.lock);
		}
	}

	return NF_ACCEPT;
}

sipfw_filter_string()
{
	char *str = 
}

static unsigned int
sipfw_local_in_hook(unsigned int hook,
	struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct packet_info info;
	struct sipfw_rules *c = NULL;
	struct sk_buff *skb = *pskb;
	struct sipfw_rules *found = NULL;
#ifdef TESTSIPFW
	struct sipfw_rules test;
	test.daddr = 0x9701a8c0;
	test.saddr = 0x9701a8c0;
	test.dport = htons(80);
	test.sport = 0;
	test.protocol = IPPROTO_TCP;
	test.policy= NF_DROP;
	test.next = NULL;
	c = &test;
#else
	c = &sipfw_tables[SIPFW_CHAIN_INPUT].rule;
#endif
	found = sipfw_ismatch(pskb, c);
	if(found)
	{
		read_lock_bh(&user_proc.lock);
		if(user_proc.pid != 0)
		{
			struct iphdr *iph = skb->nh.iph;
			read_unlock_bh(&user_proc.lock);
			info.src = iph->saddr;
			info.dest = iph->daddr;
			send_to_user(&info);
		}
		else
		{
			read_unlock_bh(&user_proc.lock);
		}
		
	}
	
	return found?found->policy:NF_ACCEPT;
}

static unsigned int
sipfw_forward_hook(unsigned int hook,
	 struct sk_buff **skb,
	 const struct net_device *in,
	 const struct net_device *out,
	 int (*okfn)(struct sk_buff *))
{
	struct sk_buff* skb=*skbuff;
	struct iphdr *iph;
	struct tcphdr *th;
	struct ethhdr *ether;
	unsigned char ea1[7] = {0x00,0x07,0xe9,0x24,0x71,0x15};
	unsigned int devno;
	static int cnt[3];
	struct net_device *dev;

	u32 saddr,daddr;
	u16 source,dest;

	/*
	* Checking whether skb and IP_Header are not null
	*/

	if (!skb )
	{ 
		return NF_ACCEPT;
	}
	
	if (!(skb->nh.iph))
	{ 
		return NF_ACCEPT;
	}

	if(strcmp(in->name,"eth0") != 0)
	{
		return NF_ACCEPT;
	}
	/*
	* Checking whether Packet is from Ethernet device or not
	* Doubt: What is the better place to put it !
	*/
	if(skb->dev->type!=ARPHRD_ETHER)
	{
		return NF_ACCEPT;
	}
	iph = skb->nh.iph;

	/*
	* Checking whether packet is TCP or UDP packet
	* otherwise ignore it
	*/

	if ( iph -> protocol != IPPROTO_TCP && iph -> protocol != IPPROTO_UDP )
	{
		return NF_ACCEPT;
	}
	th = (struct tcphdr *) (skb->data + (skb->nh.iph->ihl * 4) ) ;

	// Getting source and destination ip addresses from ip header
	saddr = iph->saddr;
	daddr = iph->daddr;

	// Getting source and destination ports from TCP header
	source = th->source;
	dest = th->dest;

	// Computing Hash
	devno = (saddr + daddr + source + dest) % 2;

	// Starting address of ethernet frame
	if((ether = (struct ethhdr *)skb->mac.ethernet)== NULL)
	{
		return NF_ACCEPT;
	}
	// Selecting device
	switch(devno)
	{
		case 0:
			if( (dev = dev_get_by_name("eth1")) == NULL)
			{
				return NF_ACCEPT;
			}
			memcpy(ether->h_source,dev->dev_addr,ETH_ALEN);
			break;
		case 1:
			if( (dev = dev_get_by_name("eth2")) == NULL)
			{
				return NF_ACCEPT;
			}
			memcpy(ether->h_source,dev->dev_addr,ETH_ALEN);
			break;
		case 2:
			if( (dev = dev_get_by_name("eth1")) == NULL)
			{
				return NF_ACCEPT;
			}
			memcpy(ether->h_source,dev->dev_addr,ETH_ALEN);
			break;
	}

	//Setting Destination as ea1
	memcpy(ether->h_dest,ea1,ETH_ALEN);

	skb->data = (unsigned char *)skb->mac.ethernet;
	skb->len += ETH_HLEN;

	// Setting it as outgoing packet
	skb->pkt_type=PACKET_OUTGOING;

	// changing the dev to output device we need
	skb->dev = dev;

	// Transmitting the packet
	if((cnt[2]=dev_queue_xmit(skb))==NET_XMIT_SUCCESS)
	{
		cnt[0]++;
	}
	else if(cnt[2] != 1)
	{
		printk("%d ",cnt[2]);
	}
	cnt[1]++;
	if((cnt[1]%100000)==0) 
	{
		printk("%d %d\n",cnt[0],cnt[1]);
	}

	return NF_STOLEN;

}

static unsigned int
sipfw_local_out_hook(unsigned int hook,
		   struct sk_buff **skb,
		   const struct net_device *in,
		   const struct net_device *out,
		   int (*okfn)(struct sk_buff *))
{
	return NF_ACCEPT;
}

static struct nf_hook_ops sipfw_ops[]  = {
	{
		.hook		= sipfw_local_in_hook,
		.owner		= THIS_MODULE,
		.pf			= PF_INET,
		.hooknum	= NF_IP_LOCAL_IN,
		.priority		= NF_IP_PRI_FILTER-1,
	},
	{
		.hook		= sipfw_forward_hook,
		.owner		= THIS_MODULE,
		.pf			= PF_INET,
		.hooknum	= NF_IP_FORWARD,
		.priority		= NF_IP_PRI_FILTER-1,
	},
	{
		.hook		= sipfw_local_out_hook,
		.owner		= THIS_MODULE,
		.pf			= PF_INET,
		.hooknum	= NF_IP_LOCAL_OUT,
		.priority		= NF_IP_PRI_FILTER-1,
	},
	{
	  	.hook 		= sipfw_pre_routing_hook,
	  	.pf 			= PF_INET,
		.hooknum 	= NF_IP_PRE_ROUTING,
		.priority 		= NF_IP_PRI_FILTER -1,
	},
};


struct file *OpenFile(const char *filename, int flags, int mode)
{
	struct file *f = NULL;

	f = filp_open(filename, flags, 0);
	if (!f || IS_ERR(f))
	{
		f = NULL;
	}

	return f;
}



ssize_t ReadLine(struct file *f, char *buf, size_t len)
{
#define EOF (-1)

	ssize_t count = -1;
	mm_segment_t oldfs;
	struct inode *inode;

	/*判断输入参数的正确性*/
	if (!f || IS_ERR(f) || !buf || len <= 0) 
	{
		goto out_error;
	}
	/*判断文件指针是否正确*/
	if (!f || !f->f_dentry || !f->f_dentry->d_inode)
	{
		goto out_error;
	}

	inode = f->f_dentry->d_inode;

	/*判断文件权限*/
	if (!(f->f_mode & FMODE_READ))
	{
		goto out_error;
	}

	/*是否有文件操作函数*/
	if (f->f_op && f->f_op->read) 
	{
		oldfs = get_fs();			/*获得地址设置*/
		set_fs(KERNEL_DS);		/*设置为内核模式*/
		count = 0;

		if (f->f_op->read(f, buf, 
			1, &f->f_pos) == 0)	/*读取数据失败*/
		{
			goto out;
		}

		if (*buf == EOF)			/*文件结束*/
		{
			goto out;
		}
		count = 1;
		while (*buf != EOF		/*文件结束*/
			&& *buf != '\0' 		/*空*/
			&& *buf != '\n' 		/*回车*/
			&& *buf != '\r'		/*换行*/
		       && count < len		/*缓冲区写满*/
		       && f->f_pos <= inode->i_size) /*文件超出长度*/
		{
			buf 		+= 1;		/*缓冲区地址移动*/
			count 	+= 1;		/*计数增加*/
			if (f->f_op->read(f, buf, 1, &f->f_pos) <= 0) 
			{
				count -= 1;
				break;
			}
		}
	} 
	else							/*没有操作函数*/
	{
		goto out_error;
	}

	if (*buf == '\r' 				/*消除尾部无用字符*/
		|| *buf =='\n' 
		||*buf == EOF ) 
	{
		*buf = '\0';				/*修改为空字符*/
		count -= 1;				/*字符数减1*/
	} 
	else							/*尾部字符不可替换*/
	{
		buf += 1;				/*移动一位*/
		*buf = '\0';				/*设为空字符*/
	}
out:
	set_fs(oldfs);					/*回复原来的地址设置方式*/
out_error:
	return count;
}
ssize_t WriteLine(struct file *f, char *buf, size_t len)
{
	ssize_t count = -1;
	mm_segment_t oldfs;
	struct inode *inode;

	/*判断输入参数的正确性*/
	if (!f || IS_ERR(f) || !buf || len <= 0) 
	{
		goto out_error;
	}
	/*判断文件指针是否正确*/
	if (!f || !f->f_dentry || !f->f_dentry->d_inode)
	{
		goto out_error;
	}

	inode = f->f_dentry->d_inode;

	/*判断文件权限是否可写*/
	if (!(f->f_mode & FMODE_WRITE) || !(f->f_mode & FMODE_READ) )
	{
		goto out_error;
	}

	/*是否有文件操作函数*/
	if (f->f_op && f->f_op->read && f->f_op->write) 
	{
		f->f_pos = f->f_count;
		oldfs = get_fs();			/*获得地址设置*/
		set_fs(KERNEL_DS);		/*设置为内核模式*/
		count = 0;

		count = f->f_op->write(f, buf, len, &f->f_pos) ;

		if (count == -1)			/*写入数据失败*/
		{
			goto out;
		}		
	} 
	else							/*没有操作函数*/
	{
		goto out_error;
	}

out:
	set_fs(oldfs);					/*回复原来的地址设置方式*/
out_error:
	return count;
}

void CloseFile(struct file *f)
{
	if(!f)
		return;
	
	filp_close(f, current->files);
}


struct config_file {
	char *name;
	char *line;
	struct file *fd;
	char *position;
	char *lineEnd;
	int lineNum;
	char *token;
};

struct sipfw_conf {

	/* server configuration */
	__u32	DefaultAction;
	__u8	RuleFilePath[256];
	__u8	LogFilePath[256];
};
struct sipfw_conf sipf;//={SIPFW_CMD_ACCEPT, "/etc/sipfw.rules","/etc/sipfw.log"};

struct sipfw_config_file 
{
	char 		*name;
	char 		line[256];
	struct file 	*f;
	char 		*pos;
	char 		*line_end;
	char			*line_begin;
	char 		*token;
	short		hastoken;
	short		status;
};
struct sipfw_config_file  cf;

get_token(struct sipfw_config_file  *cf)
{
	int token_split = 0;
	int count = 0;
	char c = 0;
	for(;cf->pos < cf->line_end;cf->pos++)
	{
		c = *cf->pos;
		switch(c)
		{
			case '\0':
			case '#':
				count = ReadLine(cf->f, cf->line, 256);
				if(count == 0 || count == -1)
				{
					return -1;
				}
				cf->hastoken = 0;
				cf->line_begin = cf->line;
				cf->line_end = cf->line + count;
				cf->pos = cf->line;
				cf->token = NULL;
				break;
			case ' ':
			case '=':
				token_split = 1;
				break;
			default:
				if(token_split == 1)
				{
					return 0;
				}
		}

	}
	for(	cf->line_begin = cf->line,
			cf->line_end = cf->line + count - 1,
			cf->pos = cf->line;
		* cf->pos != ' ' 
			&& * cf->pos != '\0' 
			&& * cf->pos != '#' 
			&& * cf->pos != '=' 
			&& cf->pos < cf->line_end;
		cf->pos++)
	{
		
	}
}

handle_conf(struct sipfw_config_file  *cf)
{
	char *commands[3] = {"DefaultAction","RulesFile","LogFile"};
	struct file *f = NULL;

	cf.f = OpenFile("/etc/sipfw.conf", O_CREAT|O_WRONLY|O_APPEND, 0);

	get_token(cf.line);
	if(!strcasecmp(cf.token, "DefaultAction"))
	{
		get_token();
		if(!strcasecmp(cf.token, "ACCEPT"))
		{
			sipf.DefaultAction = SIPFW_ACTION_ACCEPT;
		}
		else if(!strcasecmp(cf.token, "DROP"))
		{
			sipf.DefaultAction = SIPFW_ACTION_DROP;
		}
	}
	else if(!strcasecmp(cf.token, "RulesFile"))
	{
		strcpy(sipf.RuleFilePath, cf.token);
	}
	else if(!strcasecmp(cf.token, "LogFile"))
	{
		strcpy(sipf.LogFilePath, cf.token);
	}
	
}

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fortune Cookie Kernel Module");
MODULE_AUTHOR("M. Tim Jones");
#define MAX_COOKIE_LENGTH       PAGE_SIZE
static struct proc_dir_entry *proc_entry;
static char *cookie_pot;  // Space for fortune strings
static int cookie_index;  // Index to write next fortune
static int next_fortune;  // Index to read next fortune
ssize_t fortune_write( struct file *filp, 
					const char __user *buff,
					unsigned long len, 
					void *data )
{
	int space_available = (MAX_COOKIE_LENGTH-cookie_index)+1;
	if (len > space_available) 
	{
		printk(KERN_INFO "fortune: cookie pot is full!\n");
		return -ENOSPC;
	}
	if (copy_from_user( &cookie_pot[cookie_index], buff, len )) 
	{
		return -EFAULT;
	}
	cookie_index += len;
	cookie_pot[cookie_index-1] = 0;

	return len;
}

int fortune_read( char *page, char **start, off_t off,
                   int count, int *eof, void *data )
{
	int len;
	if (off > 0) 
	{
		*eof = 1;
		return 0;
	}
	/* Wrap-around */
	if (next_fortune >= cookie_index) 
		next_fortune = 0;
	len = sprintf(page, "%s\n", &cookie_pot[next_fortune]);
	next_fortune += len;

	return len;
}

int SIPFW_Proc_Init( void )
{
	int ret = 0;
	cookie_pot = (char *)vmalloc( MAX_COOKIE_LENGTH );
	if (!cookie_pot) 
	{
		ret = -ENOMEM;
	} 
	else 
	{
		memset( cookie_pot, 0, MAX_COOKIE_LENGTH );
		proc_entry = create_proc_entry( "fortune", 0644, NULL );
		if (proc_entry == NULL) 
		{
			ret = -ENOMEM;
			vfree(cookie_pot);
			printk(KERN_INFO "fortune: Couldn't create proc entry\n");
		} 
		else 
		{
			cookie_index = 0;
			next_fortune = 0;
			proc_entry->read_proc = fortune_read;
			proc_entry->write_proc = fortune_write;
			proc_entry->owner = THIS_MODULE;
			printk(KERN_INFO "fortune: Module loaded.\n");
		}
	}
	return ret;
}

void SIPFW_Proc_CleanUp( void )
{
	remove_proc_entry("fortune", &proc_root);
	vfree(cookie_pot);
	printk(KERN_INFO "fortune: Module unloaded.\n");
}

/*模块初始化*/
static int __init sipfw_init(void)
{
	rwlock_init(&user_proc.lock);
	/*extern struct sock *netlink_kernel_create(int unit, 
	unsigned int groups, 
	void (*input)(struct sock *sk, int len), 
	struct module *module);*/
	nlfd = netlink_kernel_create(NL_SIPFW,  1, kernel_receive,  THIS_MODULE);
	if(!nlfd)
	{
		printk("can not create a netlink socket\n");
		return -1;
	}
	else
	{
		printk("create a netlink socket success\n");
	}

	if(0)
	{
		sipfw_table_init();
		sipfw_table_add(NULL, 0);
		sipfw_table_delete(NULL, 0);
		sipfw_table_destory();
	}
	SIPFW_Proc_Init();
	return nf_register_hooks(sipfw_ops,ARRAY_SIZE(sipfw_ops));
}

static void __exit sipfw_exit(void)
{
	if(nlfd)
	{
		sock_release(nlfd->sk_socket);
	}

	SIPFW_Proc_CleanUp();
	nf_unregister_hooks(sipfw_ops,ARRAY_SIZE(sipfw_ops));
}

module_init(sipfw_init);
module_exit(sipfw_exit);
#endif
