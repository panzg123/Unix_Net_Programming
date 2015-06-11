#include "sip.h"

static struct net_device ifdevice;
struct net_device *get_netif()
{
	return &ifdevice;
}
void DISPLAY_MAC(struct ethhdr* eth)
{
	printf("From:%02x-%02x-%02x-%02x-%02x-%02x          ",
		eth->h_source[0],		eth->h_source[1],		eth->h_source[2],
		eth->h_source[3],		eth->h_source[4],		eth->h_source[5]);
	printf("to:%02x-%02x-%02x-%02x-%02x-%02x\n",
		eth->h_dest[0],		eth->h_dest[1],		eth->h_dest[2],
		eth->h_dest[3],		eth->h_dest[4],		eth->h_dest[5]);

}
static __u8 input(struct skbuff *pskb, struct net_device *dev)
{
	DBGPRINT(DBG_LEVEL_TRACE,"==>input\n");
	char ef[ETH_FRAME_LEN];  							/*以太帧缓冲区,1514字节*/
	int n,i;
	int retval = 0;

	/*读取以太网数据，n为返回的实际捕获的以太帧的帧长*/
	n = read(dev->s, ef, ETH_FRAME_LEN);
	if(n <=0)											/*没有读到数据*/
	{
		DBGPRINT(DBG_LEVEL_ERROR,"Not datum\n");
		retval = -1;
		goto EXITinput;								/*退出*/
	}
	else												/*读到数据*/
	{
		DBGPRINT(DBG_LEVEL_NOTES,"%d bytes datum\n", n);
	};

	struct skbuff *skb = skb_alloc(n);					/*申请存放刚才读取到数据的空间*/
	if(!skb)											/*申请失败*/
	{
		retval = -1;
		goto EXITinput;								/*退出*/
	}

	memcpy(skb->head, ef, n);							/*将接收到的网络数据拷贝到skb结构*/
	skb->tot_len =skb->len= n;							/*设置长度值*/
	skb->phy.ethh= (struct sip_ethhdr*)skb_put(skb, sizeof(struct sip_ethhdr));/*获得以太网头部指针*/
	if(samemac(skb->phy.ethh->h_dest, dev->hwaddr) 	/*数据发往本机?*/
		|| samemac(skb->phy.ethh->h_dest, dev->hwbroadcast))/*广播数据?*/
	{
		switch(htons(skb->phy.ethh->h_proto))			/*查看以太网协议类型*/
		{
			case ETH_P_IP:							/*IP类型*/
				skb->nh.iph = (struct sip_iphdr*)skb_put(skb, sizeof(struct sip_iphdr));/*获得IP头部指针*/
				/*将刚才接收到的网络数据用来更新ARP表中的映射关系*/
				arp_add_entry(skb->nh.iph->saddr, skb->phy.ethh->h_source, ARP_ESTABLISHED);

				ip_input(dev, skb);					/*交给IP层处理数据*/
				break;
			case ETH_P_ARP:							/*ARP类型*/
			{
				skb->nh.arph = (struct sip_arphdr*)skb_put(skb, sizeof(struct sip_arphdr));/*获得ARP头部指针*/
				if(*((__be32*)skb->nh.arph->ar_tip) == dev->ip_host.s_addr)	/*目的IP地址为本机?*/
				{
					arp_input(&skb, dev);				/*ARP模块处理接收到的ARP数据*/
				}
				skb_free(skb);						/*释放内存*/
			}
				break;
			default:									/*默认操作*/
				DBGPRINT(DBG_LEVEL_ERROR,"ETHER:UNKNOWN\n");
				skb_free(skb);						/*释放内存*/
				break;
		}
	}
	else
	{
		skb_free(skb);								/*释放内存*/
	}

EXITinput:
	DBGPRINT(DBG_LEVEL_TRACE,"<==input\n");
	return 0;
}

static __u8 output(struct skbuff *skb, struct net_device *dev)
{
	DBGPRINT(DBG_LEVEL_TRACE,"==>output\n");
	int retval = 0;

	struct arpt_arp  *arp = NULL;
	int times = 0,found = 0;

	/*发送网络数据的目的IP地址为skb所指的目的地址*/
	__be32 destip = skb->nh.iph->daddr;
	/*判断目的主机和本机是否在同一个子网上*/
	if((skb->nh.iph->daddr & dev->ip_netmask.s_addr )
		!= (dev->ip_host.s_addr & dev->ip_netmask.s_addr))
	{
		destip = dev->ip_gw.s_addr;		/*不在同一个子网上,将数据发送给网关*/
	}
	/*分5次查找目的主机的MAC地址*/
	while((arp = 	arp_find_entry(destip)) == NULL && times < 5)	/*查找MAC地址*/
	{
		arp_request(dev,destip);			/*没有找到,发送ARP请求*/
		sleep(1);							/*等一会*/
		times ++;						/*计数增加*/
	}

	if(!arp)								/*没有找到对应的MAC地址*/
	{
		retval = 1;
		goto EXIToutput;
	}
	else									/*找到一个对应项*/
	{
		struct sip_ethhdr *eh = skb->phy.ethh;
		memcpy(eh->h_dest, arp->ethaddr, ETH_ALEN);	/*设置目的MAC地址为项中值*/
		memcpy(eh->h_source, dev->hwaddr, ETH_ALEN);	/*设置源MAC地址为本机MAC值*/
		eh->h_proto = htons(ETH_P_IP);					/*以太网的协议类型设置为IP*/
		dev->linkoutput(skb,dev);						/*发送数据*/
	}
EXIToutput:
	DBGPRINT(DBG_LEVEL_TRACE,"<==output\n");
	return retval;
}

static __u8 lowoutput(struct skbuff *skb, struct net_device *dev)
{
	DBGPRINT(DBG_LEVEL_TRACE,"==>lowoutput\n");

	int n = 0;
	int len = sizeof(struct sockaddr);
	struct skbuff *p =NULL;
	/*将skbuff链结构中的网络数据发送出去*/
	for(p=skb;												/*从skbuff的第一个结构开始*/
		p!= NULL;											/*到末尾一个结束*/
		skb= p, p=p->next, skb_free(skb),skb=NULL)			/*发送完一个数据报文后移动指针并释放结构内存*/
	{
		n = sendto(dev->s, skb->head, skb->len,0, &dev->to, len);/*发送网络数据*/
		DBGPRINT(DBG_LEVEL_NOTES,"Send Number, n:%d\n",n);
	}

	DBGPRINT(DBG_LEVEL_TRACE,"<==lowoutput\n");

	return 0;
}

static void sip_init_ethnet(struct net_device *dev)
{
	DBGPRINT(DBG_LEVEL_TRACE, "==>sip_init_ethnet\n");

	memset(dev, 0, sizeof(struct net_device));					/*初始化网络设备*/

	dev->s = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));	/*建立一个SOCK_PACKET套接字*/
	if(dev->s > 0)											/*成功*/
	{
		DBGPRINT(DBG_LEVEL_NOTES,"create SOCK_PACKET fd success\n");
	}
	else														/*失败*/
	{
		DBGPRINT(DBG_LEVEL_ERROR,"create SOCK_PACKET fd falure\n");
		exit(-1);
	}
	/*将此套接字绑定到网卡eth1上*/
	strcpy(dev->name, "eth1");									/*拷贝eth1到name*/
	memset(&dev->to, '\0', sizeof(struct sockaddr));				/*清零to地址结构*/
	dev->to.sa_family = AF_INET;								/*协议族*/
	strcpy(dev->to.sa_data, dev->name);  						/*to的网卡名称*/
	int r = bind(dev->s, &dev->to, sizeof(struct sockaddr));		/*绑定套接字s到eth1上*/

	memset(dev->hwbroadcast, 0xFF, ETH_ALEN);					/*设置以太网的广播地址*/
#if 0
	dev->hwaddr[0] = 0x00;
	dev->hwaddr[1] = 0x12;
	dev->hwaddr[2] = 0x34;
	dev->hwaddr[3] = 0x56;
	dev->hwaddr[4] = 0x78;
	dev->hwaddr[5] = 0x90;
#else
	/*设置MAC地址*/
	dev->hwaddr[0] = 0x00;
	dev->hwaddr[1] = 0x0c;
	dev->hwaddr[2] = 0x29;
	dev->hwaddr[3] = 0x73;
	dev->hwaddr[4] = 0x9D;
	dev->hwaddr[5] = 0x1F;
#endif
	dev->hwaddr_len = ETH_ALEN;							/*设置硬件地址长度*/
#if 0
	dev->ip_host.s_addr = inet_addr("192.168.1.250");
	dev->ip_gw.s_addr = inet_addr("192.168.1.1");
	dev->ip_netmask.s_addr = inet_addr("255.255.255.0");
	dev->ip_broadcast.s_addr = inet_addr("192.168.1.255");

	dev->ip_host.s_addr = inet_addr("10.10.10.250");
	dev->ip_gw.s_addr = inet_addr("10.10.10..1");
	dev->ip_netmask.s_addr = inet_addr("255.255.255.0");
	dev->ip_broadcast.s_addr = inet_addr("10.10.10.255");
#else
	dev->ip_host.s_addr = inet_addr("172.16.12.250");		/*设置本机IP地址*/
	dev->ip_gw.s_addr = inet_addr("172.16.12.1");		/*设置本机的网关IP地址*/
	dev->ip_netmask.s_addr = inet_addr("255.255.255.0");	/*设置本机的子网掩码地址*/
	dev->ip_broadcast.s_addr = inet_addr("172.16.12.255");/*设置本机的广播IP地址*/
#endif
	dev->input = input;								/*挂机以太网输入函数*/
	dev->output = output;							/*挂接以太网输出函数*/
	dev->linkoutput = lowoutput;						/*挂接底层输出函数*/
	dev->type = ETH_P_802_3;							/*设备的类型*/
	DBGPRINT(DBG_LEVEL_TRACE,"<==sip_init_ethnet\n");
}

struct net_device * sip_init(void)
{
	sip_init_ethnet(&ifdevice);						/*初始化网络设备ifdevice*/

	return &ifdevice;									/*返回ifdevice*/
}
