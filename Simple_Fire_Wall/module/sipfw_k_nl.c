#ifndef __KERNEL__
#define __KERNEL__
#endif /*__KERNEL__*/
#ifndef MODULE
#define MODULE
#endif /*MODULE*/
#include "sipfw.h"

static struct sock *nlfd = NULL;

/*向用户发送数据*/
static int SIPFW_NLSendToUser(struct nlmsghdr *to, void *data, int len, int type)
{
	int size = 0;
	struct nlmsghdr *nlmsgh = NULL;
	char *pos = NULL;
	struct sk_buff *skb = alloc_skb(len, GFP_ATOMIC);	/*申请资源存放用户数据*/
	unsigned char *oldtail = skb->tail;			/*网络数据的结尾*/
	
	DBGPRINT("==>SIPFW_NLSendToUser\n");
	size = NLMSG_SPACE(len);		/*加消息头部的长度*/
	nlmsgh = NLMSG_PUT(skb, 0, 0, type, size-sizeof(*to));/*设置消息类型*/
	pos = NLMSG_DATA(nlmsgh);/*获得消息的数据部分地址*/
	memset(pos, 0, len);/*清空信息*/
	memcpy(pos, data, len);/*将数据拷贝过来*/

	nlmsgh->nlmsg_len = skb->tail - oldtail;/*获得消息的长度*/
	
	NETLINK_CB(skb).dst_group = 0;/*单播设定*/
	netlink_unicast(nlfd, skb, to->nlmsg_pid, MSG_DONTWAIT);	/*单播发送*/

	DBGPRINT("<==SIPFW_NLSendToUser\n");
	return 0;
 nlmsg_failure:/*NL设置失败的转跳*/
 	if(skb)
		kfree_skb(skb);/*释放资源*/

	DBGPRINT("<==SIPFW_NLSendToUser\n");
	return -1;
}

/*获得规则列表命令的处理函数*/
static int SIPFW_NLAction_RuleList(struct sipfw_rules *rule, struct nlmsghdr * to)
{
	int i ,num;
	unsigned int count = -1;
	struct sipfw_list *l = NULL;
	struct sipfw_rules *cur = NULL;
	
	DBGPRINT("==>SIPFW_NLAction_RuleList\n");
	if(rule->chain == SIPFW_CHAIN_ALL)/*获得全部三个链的规则信息*/
	{
		i = 0;/*起始链*/
		num = 3;/*链数量*/
		count = sipfw_tables[0].number /*规则个数*/
				+ sipfw_tables[1].number 
				+sipfw_tables[2].number ;
	}
	else
	{
		i = rule->chain;/*单个链的地址*/
		num = i+1;/*数量*/
		count = sipfw_tables[i].number;/*规则个数*/
	}

	/*先向客户端发送规则个数，便于应用程序计算*/
	SIPFW_NLSendToUser( to, &count, sizeof(count), SIPFW_MSG_RULE);

	for(;i<num; i++)/*循环读取规则并发送给用户空间*/
	{		
		l = &sipfw_tables[i];/*链表起始地址*/
		for(cur = l->rule; cur != NULL; cur = cur->next)/*遍历*/
		{
			if(cur)/*非空*/
			{
				/*发送给用户空间此规则*/
				SIPFW_NLSendToUser( to, cur, sizeof(*cur), SIPFW_MSG_RULE);
			}
		}
	}
	/*清空传进来的规则*/
	kfree(rule);

	DBGPRINT("<==SIPFW_NLAction_RuleList\n");
	return 0;
}

/*增加规则列表*/
static int SIPFW_NLAction_RuleAddpend(struct sipfw_rules *rule)
{
	struct sipfw_list *l = &sipfw_tables[rule->chain];/*加入的链*/

	struct sipfw_rules *prev = NULL;
	struct sipfw_rules *cur = NULL;
	DBGPRINT("==>SIPFW_NLAction_RuleAddpend\n");
	DBGPRINT("addpend to chain:%d==>%s,source:%x,dest:%x\n",
		rule->chain,
		(char*)sipfw_chain_name[rule->chain].ptr,
		rule->source,
		rule->dest);
	if(l->rule == NULL)/*链为空*/
	{
		l->rule = rule;/*加到头部*/
	}
	else/*不为空*/
	{
		/*找到这个链的末尾*/
		for(cur = l->rule; cur != NULL; prev = cur, cur = cur->next)
			;
		prev->next = rule;/*挂接*/
	}	

	l->number++;/*本链上的规则个数增加*/

	DBGPRINT("<==SIPFW_NLAction_RuleAddpend\n");
	return 0;
}

/*删除规则列表，如果number有效则删除此规则，
*否则按照传入的规则删除*/
static int SIPFW_NLAction_RuleDelete(struct sipfw_rules *rule, int number)
{
	struct sipfw_list *l = &sipfw_tables[rule->chain];/*在哪个链上删除*/
	int i = 0;

	struct sipfw_rules *prev = NULL;
	struct sipfw_rules *cur = NULL;
	DBGPRINT("==>SIPFW_NLAction_RuleDelete\n");
	if(number > l->number)/*位置参数过大*/
	{
		kfree(rule);/*不动作*/
	}
	else if(number != -1)/*位置参数有效*/
	{
		/*查找合适的位置*/
		for(cur = l->rule, i= 1; cur != NULL && i !=number; prev = cur, cur = cur->next,i++)
			;
		if(cur != NULL)/*到达末尾*/
		{
			if(prev == NULL)/*删除第一个规则*/
			{
				l->rule = cur->next;/*更新头部指针*/
			}
			else/*中间的规则*/
			{
				prev->next = cur->next;
			}
			kfree(cur);/*释放资源*/
			l->number--;		/*本链的规则个数减1*/
		}
		kfree(rule);/*释放传入的规则*/
	}	 
	else/*位置参数没有输入*/
	{
		/*在链上查找规则匹配的项来删除*/
		for(cur=l->rule; cur != NULL; prev = cur, cur=cur->next)
		{
			if(	cur->action == rule->action/*动作匹配*/
				&&cur->addtion.valid == rule->addtion.valid/*附加项匹配*/
				&&cur->chain ==rule->chain/*链名称匹配*/
				&&cur->source == rule->source /*源地址匹配*/
				&&cur->dest == rule->dest/*目的地址匹配*/
				&&cur->sport==rule->sport/*源端口匹配*/
				&&cur->dport==rule->dport/*目的端口匹配*/
				&&cur->protocol==rule->protocol)/*协议匹配*/
			{
				if(!prev)/*头部*/
				{
					l->rule = cur->next;/*头部指针更新*/
				}
				else/*中间*/
				{
					prev->next = cur->next;
				}

				kfree(cur);/*释放资源*/
				l->number --;/*数量减少1*/
				kfree(rule);/*释放传入的规则*/
				break;
			}
		}
	}

	DBGPRINT("<==SIPFW_NLAction_RuleDelete\n");
	return 0;
}

/*替换规则列表*/
static int SIPFW_NLAction_RuleReplace(struct sipfw_rules *rule, int number)
{
	struct sipfw_list *l = &sipfw_tables[rule->chain];
	int i = 0;

	struct sipfw_rules *prev = NULL;
	struct sipfw_rules *cur = NULL;
	DBGPRINT("==>SIPFW_NLAction_RuleReplace\n");
	if(number != -1)/*数值正确*/
	{
		/*查找合适的位置*/
		for(cur = l->rule, i= 1; cur != NULL && i !=number; prev = cur, cur = cur->next,i++)
			;
		if(cur != NULL)/*找到被替换项*/
		{
			if(prev == NULL)/*头部*/
			{
				l->rule = rule;
			}
			else/*中间*/
			{
				prev->next = rule;
			}
			rule->next = cur->next;/*摘除被替换项*/
			kfree(cur);/*释放资源*/
		}
	}
	else if(number > l->number)
	{
		kfree(rule);/*没有找到，释放传入指针*/
	}
	
	DBGPRINT("<==SIPFW_NLAction_RuleReplace\n");
	return 0;
}

/*插入规则到规则列表某个位置*/
static int SIPFW_NLAction_RuleInsert(struct sipfw_rules *rule, int number)
{
	struct sipfw_list *l = &sipfw_tables[rule->chain];
	int i = 0;

	struct sipfw_rules *prev = NULL;
	struct sipfw_rules *cur = NULL;

	DBGPRINT("==>SIPFW_NLAction_RuleInsert\n");
	if(number == 1)/*插入头部*/
	{
		rule->next = l->rule;
		l->rule = rule;
		goto EXITSIPFW_NLAction_RuleInsert;
	}

	if(number > l->number)/*插入尾部*/
	{
		/*查找该位置*/
		for(cur = l->rule; cur != NULL; prev = cur, cur = cur->next)
			;
		prev->next = rule;
		goto EXITSIPFW_NLAction_RuleInsert;
	}
	
	if(number != -1)/*位置正确*/
	{
		for(cur = l->rule, i= 1; cur != NULL && i <number; prev = cur, cur = cur->next,i++)
			;
		prev->next = rule;
		rule->next = cur->next;
	}
EXITSIPFW_NLAction_RuleInsert:	
	DBGPRINT("<==SIPFW_NLAction_RuleInsert\n");
	return 0;
}

/*清空规则列表*/
static int SIPFW_NLAction_RuleFlush(struct sipfw_rules *rule)
{
	struct sipfw_list *l = NULL;
	struct sipfw_rules *prev = NULL;
	struct sipfw_rules *cur = NULL;
	int i ,num;
	DBGPRINT("==>SIPFW_NLAction_RuleFlush\n");
	if(rule->chain == SIPFW_CHAIN_ALL)/*全部清除*/
	{
		i = 0;
		num = 3;
	}
	else/*清除一个链表*/
	{
		i = rule->chain;
		num = i+1;
	}

	for(;i<num; i++)/*循环清除*/
	{
		
		l = &sipfw_tables[i];
		for(cur = l->rule; cur != NULL; prev = cur, cur = cur->next)
		{
			if(prev)
			{
				kfree(prev);
			}
		}
		l->rule = NULL;
		l->number = 0;
	}

	kfree(rule);

	DBGPRINT("<==SIPFW_NLAction_RuleFlush\n");
	return 0;
}

/*响应客户端的动作*/
static int SIPFW_NLDoAction(void *payload, struct nlmsghdr* nlmsgh)
{
	struct sipfw_cmd_opts *cmd_opt = NULL;
	int cmd = -1;
	int number = -1;
	vec NLSUCCESS={"SUCCESS",8};
	vec NLFAILRE={"FAILURE",8};

	struct sipfw_rules *rule = NULL;
	DBGPRINT("==>SIPFW_NLDoAction\n");
	cmd_opt = (struct sipfw_cmd_opts *)payload;
	cmd = cmd_opt->command.v_uint;
	/*每个动作之前先申请一个单元存放规则数据，
	对此单元的内存处理由各个处理方法自己决定
	例如对于插入的规则，此内存直接由方法使用了，
	而删除规则的动作，则需要释放两个单元的内存*/
	rule = (struct sipfw_rules*)kmalloc(sizeof(struct sipfw_rules), GFP_KERNEL);
	if(!rule)
	{
		DBGPRINT("Malloc rule struct failure\n");
	}

	rule->next = NULL;

	/*初始化为默认信息*/
	rule->chain = cmd_opt->chain.v_int;
	rule->source= cmd_opt->source.v_uint;
	rule->source= cmd_opt->source.v_uint;
	rule->sport = cmd_opt->sport.v_uint;
	rule->dport = cmd_opt->dport.v_uint;
	rule->protocol = cmd_opt->protocol.v_uint;
	rule->action = cmd_opt->action.v_uint;
	rule->addtion.valid = cmd_opt->addtion.valid;
	number = cmd_opt->number.v_int;
	
//static int SIPFW_NLSendToUser(struct sock *s, struct nlmsghdr *to, void *data, int len);

	switch(cmd)
	{
		int err = -1;
		case SIPFW_CMD_INSERT:	/*向规则链中插入新规则*/
			err = SIPFW_NLAction_RuleInsert(rule, number);
			if(!err)
			{
				SIPFW_NLSendToUser( nlmsgh,NLSUCCESS.ptr, NLSUCCESS.len, SIPFW_MSG_SUCCESS);
			}
			else
			{
				SIPFW_NLSendToUser( nlmsgh,NLFAILRE.ptr, NLFAILRE.len, SIPFW_MSG_FAILURE);
			}
			break;
		case SIPFW_CMD_DELETE:	/*从规则链中删除某规则*/
			err = SIPFW_NLAction_RuleDelete(rule, number);
			if(!err)
			{
				SIPFW_NLSendToUser( nlmsgh,NLSUCCESS.ptr, NLSUCCESS.len, SIPFW_MSG_SUCCESS);
			}
			else
			{
				SIPFW_NLSendToUser( nlmsgh,NLFAILRE.ptr, NLFAILRE.len, SIPFW_MSG_FAILURE);
			}
			break;
		case SIPFW_CMD_REPLACE:/*更换某个规则*/
			err = SIPFW_NLAction_RuleReplace(rule,number);
			if(!err)
			{
				SIPFW_NLSendToUser( nlmsgh,NLSUCCESS.ptr, NLSUCCESS.len, SIPFW_MSG_SUCCESS);
			}
			else
			{
				SIPFW_NLSendToUser( nlmsgh,NLFAILRE.ptr, NLFAILRE.len, SIPFW_MSG_FAILURE);
			}
			break;
		case SIPFW_CMD_APPEND:	/*将新规则加到规则链末尾*/
			err = SIPFW_NLAction_RuleAddpend(rule);
			if(!err)
			{
				SIPFW_NLSendToUser( nlmsgh,NLSUCCESS.ptr, NLSUCCESS.len, SIPFW_MSG_SUCCESS);
			}
			else
			{
				SIPFW_NLSendToUser( nlmsgh,NLFAILRE.ptr, NLFAILRE.len, SIPFW_MSG_FAILURE);
			}
			break;
		case SIPFW_CMD_LIST:	/*列出规则链中的规则*/
			SIPFW_NLAction_RuleList(rule,nlmsgh);
			break;
		case SIPFW_CMD_FLUSH:/*清空规则*/
			err = SIPFW_NLAction_RuleFlush(rule);
			if(!err)
			{
				SIPFW_NLSendToUser( nlmsgh,NLSUCCESS.ptr, NLSUCCESS.len, SIPFW_MSG_SUCCESS);
			}
			else
			{
				SIPFW_NLSendToUser( nlmsgh,NLFAILRE.ptr, NLFAILRE.len, SIPFW_MSG_FAILURE);
			}
			break;
		default:
			break;
	}

	DBGPRINT("<==SIPFW_NLDoAction\n");
	return 0;
}

static void SIPFW_NLInput(struct sock *sk, int len)
{	
	__u8 *payload = NULL;
	DBGPRINT("==>SIPFW_NLInput\n");

	/*处理过程为:
	*当接收队列不为空的时候，
	*从链上摘除网络数据，
	*获取IP头部和负载部分的指针然后
	*发送给处理函数
	*/
	do{
		struct sk_buff *skb;
		/*从链上摘除网络数据*/
		while((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL)
		{
			struct nlmsghdr *nlh = NULL;
			if(skb->len >= sizeof(struct nlmsghdr))/*数据长度不对*/
			{
				nlh = (struct nlmsghdr *)skb->data;/*获得信息头部*/
				if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
					&& (skb->len >= nlh->nlmsg_len))/*合法数据*/
				{
					payload = NLMSG_DATA(nlh);/*负载部分*/
					SIPFW_NLDoAction(payload, nlh);/*处理数据*/
				}
			}
			kfree_skb(skb);
		}
	}while(nlfd && nlfd->sk_receive_queue.qlen);
	DBGPRINT("<==SIPFW_NLInput\n");
	return ;
}

/* 建立netlink套接字 */
int SIPFW_NLCreate(void)
{
	/*建立Netlink套接字，其处理的回调函数为SIPFW_NLInput*/
	nlfd = netlink_kernel_create(NL_SIPFW,  1, SIPFW_NLInput,  THIS_MODULE);
	if(!nlfd)
	{
		return -1;
	}
	
	return 0;
}
/*销毁netlink套接字*/
int SIPFW_NLDestory(void)
{
	if(nlfd)
	{
		sock_release(nlfd->sk_socket);
	}	
	return 0;
}



