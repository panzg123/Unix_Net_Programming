#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif
#include "sipfw.h"
#include "sipfw_para.h"

/*一些声明*/
MODULE_DESCRIPTION("Simple IP FireWall module ");
MODULE_AUTHOR("songjingbin<flyingfat@163.com>");

/*进入本地数据的钩子处理函数*/
static unsigned int
SIPFW_HookLocalIn(unsigned int hook,
	struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct sipfw_rules *l = NULL;/*规则链指针*/
	struct sk_buff *skb = *pskb;/*网络数据结构*/
	struct sipfw_rules *found = NULL;/*找到的规则*/
	int	retval = 0;/*返回值*/
	DBGPRINT("==>SIPFW_HookLocalIn\n");
	if(cf.Invalid)/*防火墙是否禁止*/
	{
		retval = NF_ACCEPT;/*防火墙关闭,让数据通过*/
		goto EXITSIPFW_HookLocalIn;
	}
	
	
	l = sipfw_tables[SIPFW_CHAIN_INPUT].rule;/*INPUT链*/
	found = SIPFW_IsMatch(skb, l);/*数据和链中规则是否匹配*/
	if(found)/*有匹配规则*/
	{
		SIPFW_LogAppend(skb, found);/*记录*/
		cf.HitNumber++;/*命中数增加*/
	}
	/*更新返回值*/
	retval = found?found->action:cf.DefaultAction;
EXITSIPFW_HookLocalIn:	
	DBGPRINT("<==SIPFW_HookLocalIn\n");
	return retval ;
}

/*从本地发出的网络数据处理钩子函数*/
static unsigned int
SIPFW_HookLocaOut(unsigned int hook,
	struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct sipfw_rules *l = NULL;/*规则链指针*/
	struct sk_buff *skb = *pskb;/*网络数据结构*/
	struct sipfw_rules *found = NULL;/*找到的规则*/
	int	retval = 0;/*返回值*/
	DBGPRINT("==>SIPFW_HookLocaOut\n");
	if(cf.Invalid)/*防火墙是否禁止*/
	{
		retval = NF_ACCEPT;/*防火墙关闭,让数据通过*/
		goto EXITSIPFW_HookLocaOut;
	}
	
	l = sipfw_tables[SIPFW_CHAIN_OUTPUT].rule;/*OUTPUT链*/
	found = SIPFW_IsMatch(skb, l);/*数据和链中规则是否匹配*/
	if(found)
	{
		SIPFW_LogAppend(skb, found);/*记录*/
		cf.HitNumber++;/*命中数增加*/
	}
	/*更新返回值*/
	retval = found?found->action:cf.DefaultAction;
	
EXITSIPFW_HookLocaOut:
	DBGPRINT("<==SIPFW_HookLocaOut\n");
	return retval;
}

/*从本地发出的网络数据处理钩子函数*/
static unsigned int
SIPFW_HookForward(unsigned int hook,
	struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct sipfw_rules *l = NULL;/*规则链指针*/
	struct sk_buff *skb = *pskb;/*网络数据结构*/
	struct sipfw_rules *found = NULL;/*找到的规则*/
	int	retval = 0;/*返回值*/
	DBGPRINT("==>SIPFW_HookForward\n");
	DBGPRINT("in device:%s,out device:%s\n",in->name, out->name);{
	int i =0;int len =skb->dev->addr_len;
	__u8 *mac=skb->dev->perm_addr;
	for(i=0;i<len;i++)
		DBGPRINT("%x-", mac[i]);
	mac = skb->input_dev->perm_addr;
	len = skb->input_dev->addr_len;
	DBGPRINT("\n");
	for(i=0;i<len;i++)
		DBGPRINT("%x-", mac[i]);
	DBGPRINT("\n");
	mac= skb->mac.raw;len = skb->mac_len;
	DBGPRINT("SKB MAC, len:%d\n",len);
	for(i=0;i<len;i++)
		DBGPRINT("%x-", mac[i]);
	DBGPRINT("\n");
	//00-1F-3A-B1-FA-60
	mac[6]=mac[0];
	mac[7]=mac[1];
	mac[8]=mac[2];
	mac[9]=mac[3];
	mac[10]=mac[4];
	mac[11]=0x15;
	
	mac[0]=0x00;
	mac[1]=0x1F;
	mac[2]=0x3A;
	mac[3]=0xB1;
	mac[4]=0xFA;
	mac[5]=0x60;

	
	
	

	dev_queue_xmit(skb);
	return NF_STOLEN;

	

}	if(cf.Invalid)/*防火墙是否禁止*/
	{
		retval = NF_ACCEPT;/*防火墙关闭,让数据通过*/
		goto EXITSIPFW_HookForward;
	}
	
	l = sipfw_tables[SIPFW_CHAIN_OUTPUT].rule;/*OUTPUT链*/
	found = SIPFW_IsMatch(skb, l);/*数据和链中规则是否匹配*/
	if(found)
	{
		SIPFW_LogAppend(skb, found);/*记录*/
		cf.HitNumber++;/*命中数增加*/
	}
	/*更新返回值*/
	retval = found?found->action:cf.DefaultAction;
EXITSIPFW_HookForward:
	DBGPRINT("<==SIPFW_HookForward\n");
	return retval;
}

/*从本地发出的网络数据处理钩子函数*/
static unsigned int
SIPFW_HookPreRouting(unsigned int hook,
	struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct sipfw_rules *l = NULL;/*规则链指针*/
	struct sk_buff *skb = *pskb;/*网络数据结构*/
	struct sipfw_rules *found = NULL;/*找到的规则*/
	int	retval = 0;/*返回值*/
	DBGPRINT("==>SIPFW_HookPreRouting\n");
	if(cf.Invalid)/*防火墙是否禁止*/
	{
		retval = NF_ACCEPT;/*防火墙关闭,让数据通过*/
		goto EXITSIPFW_HookPreRouting;
	}
	
	l = sipfw_tables[SIPFW_CHAIN_OUTPUT].rule;/*OUTPUT链*/
	found = SIPFW_IsMatch(skb, l);/*数据和链中规则是否匹配*/
	if(found)
	{
		SIPFW_LogAppend(skb, found);/*记录*/
		cf.HitNumber++;/*命中数增加*/
	}
	/*更新返回值*/
	retval = found?found->action:cf.DefaultAction;
EXITSIPFW_HookPreRouting:
	DBGPRINT("<==SIPFW_HookPreRouting\n");
	return retval;
}

/*从本地发出的网络数据处理钩子函数*/
static unsigned int
SIPFW_HookPostRouting(unsigned int hook,
	struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct sipfw_rules *l = NULL;/*规则链指针*/
	struct sk_buff *skb = *pskb;/*网络数据结构*/
	struct sipfw_rules *found = NULL;/*找到的规则*/
	int	retval = 0;/*返回值*/
	DBGPRINT("==>SIPFW_HookPostRouting\n");
	if(cf.Invalid)/*防火墙是否禁止*/
	{
		retval = NF_ACCEPT;/*防火墙关闭,让数据通过*/
		goto EXITSIPFW_HookPostRouting;
	}
	
	l = sipfw_tables[SIPFW_CHAIN_OUTPUT].rule;/*OUTPUT链*/
	found = SIPFW_IsMatch(skb, l);/*数据和链中规则是否匹配*/
	if(found)
	{
		SIPFW_LogAppend(skb, found);/*记录*/
		cf.HitNumber++;/*命中数增加*/
	}
	/*更新返回值*/
	retval = found?found->action:cf.DefaultAction;
EXITSIPFW_HookPostRouting:
	DBGPRINT("<==SIPFW_HookPostRouting\n");
	return retval;
}


/* 钩子挂接结构 */
static struct nf_hook_ops sipfw_hooks[]  = {
	{
		.hook		= SIPFW_HookLocalIn,	/*本地接收数据*/
		.owner		= THIS_MODULE,			/*模块所有者*/
		.pf			= PF_INET,				/*网络协议*/
		.hooknum	= NF_IP_LOCAL_IN,		/*挂接点*/
		.priority		= NF_IP_PRI_FILTER-1,		/*优先级*/
	},

	{
		.hook		= SIPFW_HookLocaOut,	/*本地发出的数据*/
		.owner		= THIS_MODULE,			/*模块所有者*/
		.pf			= PF_INET,				/*网络协议*/
		.hooknum	= NF_IP_LOCAL_OUT,		/*挂接点*/
		.priority		= NF_IP_PRI_FILTER-1,		/*优先级*/
	},
	{
		.hook		= SIPFW_HookForward,	/*本地发出的数据*/
		.owner		= THIS_MODULE,			/*模块所有者*/
		.pf			= PF_INET,				/*网络协议*/
		.hooknum	= NF_IP_FORWARD,		/*挂接点*/
		.priority		= NF_IP_PRI_FILTER-1,		/*优先级*/
	},
	{
		.hook		= SIPFW_HookPreRouting,	/*本地发出的数据*/
		.owner		= THIS_MODULE,			/*模块所有者*/
		.pf			= PF_INET,				/*网络协议*/
		.hooknum	= NF_IP_PRE_ROUTING,		/*挂接点*/
		.priority		= NF_IP_PRI_FILTER-1,		/*优先级*/
	},
	{
		.hook		= SIPFW_HookPostRouting,	/*本地发出的数据*/
		.owner		= THIS_MODULE,			/*模块所有者*/
		.pf			= PF_INET,				/*网络协议*/
		.hooknum	= NF_IP_POST_ROUTING,		/*挂接点*/
		.priority		= NF_IP_PRI_FILTER-1,		/*优先级*/
	},
};



/*模块初始化*/
static int __init SIPFW_Init(void)
{
	int ret = -1;
	DBGPRINT("==>SIPFW_Init\n");
	
	ret = SIPFW_HandleConf();/*读取防火墙配置文件*/
	
	ret =SIPFW_NLCreate();/*建立Netlink套接字准备和用户空间通信*/
	if(ret)
	{
		goto error1;
	}
	
	ret =SIPFW_Proc_Init();/*建立PROC虚拟文件*/
	if(ret)
	{
		goto error2;
	}	
	ret = nf_register_hooks(sipfw_hooks,ARRAY_SIZE(sipfw_hooks));
	if(ret)
	{
		goto error3;
	}

	goto error1;
error3:
	SIPFW_Proc_CleanUp();
error2:
	SIPFW_NLDestory();
error1:
	DBGPRINT("<==SIPFW_Init\n");
	return ret;
}

static void __exit SIPFW_Exit(void)
{
	DBGPRINT("==>SIPFW_Exit\n");
	SIPFW_NLDestory();
	SIPFW_ListDestroy();

	DBGPRINT("module sipfw exit\n");
	
	SIPFW_Proc_CleanUp();
	nf_unregister_hooks(sipfw_hooks,ARRAY_SIZE(sipfw_hooks));
	DBGPRINT("<==SIPFW_Exit\n");
}

module_init(SIPFW_Init);
module_exit(SIPFW_Exit);
MODULE_LICENSE("GPL/BSD");

