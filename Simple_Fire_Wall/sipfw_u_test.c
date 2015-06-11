#if 0
#include <unistd.h>
#include <stdio.h>
#include <linux/types.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <signal.h>
#include "../module/sipfw.h"

struct msg_to_kernel
{
	struct nlmsghdr hdr;
};

struct u_packet_info
{
	struct nlmsghdr hdr;
	struct packet_info icmp_info;
};

static int skfd;

static void sig_int(int signo)
{
	struct sockaddr_nl kpeer;
	struct msg_to_kernel message;

	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid    = 0;
	kpeer.nl_groups = 0;

	memset(&message, 0, sizeof(message));
	message.hdr.nlmsg_len = NLMSG_LENGTH(0);
	message.hdr.nlmsg_flags = 0;
	message.hdr.nlmsg_type = SIPFW_CLOSE;
	message.hdr.nlmsg_pid = getpid();

	sendto(skfd, &message, message.hdr.nlmsg_len, 0, (struct sockaddr *)(&kpeer),sizeof(kpeer));

	close(skfd);
	exit(0);
}
enum{
	CMD_NONE 			= 0x0000U,
	CMD_INSERT 		= 0x0001U,
	CMD_DELETE 		= 0x0002U,
	CMD_APPEND 		= 0x0004U,
	CMD_LIST 			= 0x0008U,
	CMD_FLUSH 			= 0x0001U,
	NUMBER_OF_CMD 	= 5
}

struct opt_value{
	unsigned int flag;
	unsigned int from;
	unsigned int to;
};

union variant {
	char			v_str[8];
	int			v_int;
	unsigned int	v_uint;
	time_t		v_time;
	void			(*v_func)(void);
	void			*v_void;
	struct vec	v_vec;
	struct opt_value v_opt;
};

struct vec {
	void *ptr;
	unsigned long len;
};


/*
 * This guy holds parsed HTTP headers
 */
struct opts_value {
	union variant	command;
	union variant	source;
	union variant	dest;
	union variant	sport;
	union variant	dport;
	union variant	protocol;
	union variant	chain;
	union variant	ifname;
};


static struct option opts_long[] = {						/*长选项*/
	{.name = "source",    	.has_arg = 1, 		.val = 's'},	/*源主机IP地址*/
	{.name = "dest",        	.has_arg = 1, 		.val = 'd'},	/*目的主机IP地址*/
	{.name = "sport",        	.has_arg = 1, 		.val = 'm'},	/*源端口地址*/
	{.name = "dport",       	.has_arg = 1, 		.val = 'n'},	/*目的端口地址*/
	{.name = "protocol", 	.has_arg = 2, 		.val = 'p'},	/*协议类型*/
	{.name = "list",    		.has_arg = 2, 		.val = 'L'},	/*规则列表*/
	{.name = "flush",         	.has_arg = 2, 		.val = 'F'},	/*清空规则*/
	{.name = "append", 	.has_arg = 2, 		.val = 'A'},	/*增加规则到链尾部*/
	{.name = "insert",     	.has_arg = 1, 		.val = 'I'},	/*向链中增加规则*/
	{.name = "delete",  	.has_arg = 2, 		.val = 'D'},	/*删除规则*/
	{.name = "interface",  	.has_arg = 1, 		.val = 'i'},	/*网络接口*/
	{NULL},
};
enum{
	OPT_IP,
	OPT_PROTOCOL,
	OPT_STR,
	OPT_INT
};

static const char opts_short[] =  "s:d:m:n:p:L:F:A:I:D:i:",;	/*短选项*/
static const vec chain_name[] = {	
	{"INPUT",	5},
	{"OUTPUT",	6},
	{"FORWARD",	7},
	{NULL,		0}  };

static const vec action_name[] = {	
	{"ACCEPT",	6},
	{"DROP",	4},
	{NULL,		0}  };
enum{
	OPT_CHAIN,
	OPT_IP,
	OPT_PORT,
	OPT_PROTOCOL,
	OPT_STR,
	OPT_VEC
};



int parse_opt(int opt, char *str, union variant *var)
{
	switch(opt)
	{
		case OPT_CHAIN:
			int chain = SIPFW_CHAIN_ALL;
			if(str){				
				int i = 0;
				
				for(i = 0;i<SIPFW_CHAIN_NUM;i++)
				{
					if(!strncmp(str, chain_name[i].ptr, chain_name[i].len))
					{
						chain = i;
						break;
					}
				}
			}
			var->v_big_int = chain;
			break;
			
		case OPT_IP:
			unsigned int ip = 0;
			if(str)
				ip = inet_addr(str);

			var->v_big_int = ip;
			break;
			
		case OPT_PORT:
			unsigned int port = 0;
			if(str)
				port = strtonl(str, NULL, strlen(str));

			var->v_big_int = port;
			
			break;
			
		case OPT_PROTOCOL:
			unsigned short proto = 0;
			if(str)
				proto = strtonl(str, NULL, strlen(str));

			proto = htons(proto);

			var->v_big_int = proto;
			break;
			
		case OPT_STR:
			break;
			
		case OPT_STR:
			if(str)
			{
				int 	len = strlen(str);
				memset(var->v_str, 0, sizeof(var->v_str));
				if(len < 8)
				{
					memcpy(var->v_str, str, len);

				}
			}
			break;

		default:
			break;
	}
}

do_command(int argc, char *argv[], 	struct opts_value *cmd_opt)
{
	unsigned int cmd = CMD_NONE;
	static char *l_opt_arg = NULL;
	cmd_opt->chain.v_uint = SIPFW_CHAIN_ALL;
	cmd_opt->command.v_uint = SIPFW_CMD_ACCEPT;
	cmd_opt->dest.v_uint = 0;
	cmd_opt->dport.v_uint = 0;
	cmd_opt->source.v_uint = 0;
	cmd_opt->sport.v_uint = 0;
	cmd_opt->protocol.v_uint = 0;
	memset(cmd_opt->ifname.v_str, 0, 8);
	
		
	char c = 0;
	while ((c = getopt_long(argc, argv, opts_short,  opts_long, NULL)) != -1) 
	{
		switch(c)
		{
			case 's':		/*源主机IP地址*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_IP, optarg, &cmd_opt->source);
				}
				
				break;
			case 'd':/*目的主机IP地址*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_IP, optarg, &cmd_opt->dest);
				}
				
				break;
			case 'm':/*源端口地址*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_PORT, optarg, &cmd_opt->sport);
				}
				
				break;
			case 'n':/*目的端口地址*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_PORT, optarg, &cmd_opt->dport);
				}
				
				break;
			case 'p':/*协议类型*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_PROTOCOL, optarg, &cmd_opt->protocol);
				}
				
				break;
			case 'L':/*规则列表*/
				cmd |= CMD_LIST;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
			case 'F':/*清空规则*/
				cmd |= CMD_FLUSH;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
				break;
			case 'A':/*增加规则到链尾部*/
				cmd |= CMD_APPEND;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
				break;
			case 'I':/*向链中增加规则*/
				cmd |= CMD_INSERT;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
				break;
			case 'D':/*删除规则*/
				cmd |= CMD_DELETE;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
				break;
			case 'i':/*网络接口*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':'){
					parse_opt(OPT_STR, optarg, &cmd_opt->ifname);
				}
				break;
			default:
				break;
		}

		
	}
}
struct iovec
{
	void  *iov_base;	/* BSD uses caddr_t (1003.1g requires void *) */
	ssize_t iov_len; /* Must be size_t (1003.1g) */
};

struct msghdr {
	void	*	msg_name;	/* Socket name			*/
	int		msg_namelen;	/* Length of name		*/
	struct iovec *	msg_iov;	/* Data blocks			*/
	ssize_t	msg_iovlen;	/* Number of blocks		*/
	void 	*	msg_control;	/* Per protocol magic (eg BSD file descriptor passing) */
	ssize_t	msg_controllen;	/* Length of cmsg list */
	unsigned	msg_flags;
};
struct nlmsghdr
{
	__u32		nlmsg_len;	/* Length of message including header */
	__u16		nlmsg_type;	/* Message content */
	__u16		nlmsg_flags;	/* Additional flags */
	__u32		nlmsg_seq;	/* Sequence number */
	__u32		nlmsg_pid;	/* Sending process PID */
};
struct sockaddr_nl
{
	sa_family_t	nl_family;	/* AF_NETLINK	*/
	unsigned short	nl_pad;		/* zero		*/
	__u32		nl_pid;		/* process pid	*/
       __u32		nl_groups;	/* multicast groups mask */
};

#include <sys/socket.h>
#include <linux/netlink.h>


void main(int argc, char *argv[]) 
{
#define MAX_PAYLOAD 1024  				/* 最大负载长度*/

	struct sockaddr_nl source, dest;		/*源地址和目标地址*/
	int s = -1;							/*套接字文件描述符*/
	struct msghdr msg;					/*与内核通信消息*/
	struct iovec iov;						/*消息中的向量*/
	char buffer[MAX_PAYLOAD];			/*nlmsghdr使用缓冲区*/
	struct nlmsghdr *nlmsgh = NULL;
	int err = -1;
	struct opts_value cmd_opt;

	do_command(argc, argv[], &cmd_opt);


	signal(SIGINT, sig_int);				/*挂接中断信号*/
	
	s = socket(PF_NETLINK, 				/*建立套接字*/
		SOCK_RAW,NETLINK_TEST);
	if(s < 0)
	{
		printf("can not create a netlink socket\n");
		return -1;
	}

	/*设置源地址*/
	memset(&source, 0, sizeof(source));		/*清空缓冲区*/
	source.nl_family 	= AF_NETLINK;		/*协议族*/
	source.nl_pid 		= getpid();  			/*本进程ID*/
	source.nl_groups 	= 0;  				/*单播*/

	err = bind(s, 							/*绑定*/
		(struct sockaddr*)&source, sizeof(source));
	{
		printf("bind() error\n");
		return -1;
	}

	memset(&dest, 0, sizeof(dest));			/*清空缓冲区*/
	dest.nl_family 	= AF_NETLINK;		/*协议族*/
	dest.nl_pid 		= 0;   				/*发送给内核*/
	dest.nl_groups 	= 0; 				/*单播*/

	nlmsgh=(struct nlmsghdr *)buffer;		/*将nlmsg结构指向缓冲区*/
	/* 填充netlink消息头*/
	nlmsgh->nlmsg_len 	= NLMSG_SPACE(MAX_PAYLOAD);/*长度*/
	nlmsgh->nlmsg_pid 	= getpid();  		/*本进程的PID*/
	nlmsgh->nlmsg_flags 	= 0;				/*标志*/
	/* 填充netlink消息的负载*/
	memcpy(NLMSG_DATA(nlmsgh), &cmd_opt, sizeof(cmd_opt));

	iov.iov_base 		= (void *)nlmsgh;		/*将netlink私有消息写入向量*/
	iov.iov_len 		= nlmsgh->nlmsg_len;	/*向量长度*/
	msg.msg_name 	= (void *)&dest;		/*消息名称为地址*/
	msg.msg_namelen = sizeof(dest);		/*名称长度*/
	msg.msg_iov 		= &iov;				/*消息向量*/
	msg.msg_iovlen 	= 1;					/*向量个数*/

	sendmsg(s, &msg, 0);					/*发送消息*/

	/* 从内核接收消息 */
	memset(nlmsgh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	recvmsg(s, &msg, 0);					/*接收消息*/
	unsigned int retval = (unsigned int *)NLMSG_DATA(nlmsgh);
	
	if(cmd_opt.command.v_uint == CMD_LIST)/*获得规则列表*/
	{		
		unsigned int sip = 0, dip = 0;		/*原IP地址和目的IP地址*/
		unsigned short sport = 0, dport = 0;	/*源端口和目的端口*/
		unsigned char proto = 0;			/*协议类型*/
		unsigned char action = 0;			/*动作类型*/
		unsigned char chain_org = SIPFW_CHAIN_NUM, chain;
		int i = 0;
		for(i = retval; i > 0; i -= 10)		/*分多次读取内核中的规则*/
		{
			int j = 0, len = 0;
			memset(nlmsgh, 0, NLMSG_SPACE(MAX_PAYLOAD));
			recvmsg(s, &msg, 0);			/*接收消息*/
			struct sipfw_rules *rules = NLMSG_DATA(nlmsgh);

			len = msg.msg_iov.iov_len/sizeof(*rules);/*规则个数*/
			for(j = 0; j < len; j++)			/*读取规则*/
			{
				action = rules->policy;		/*动作*/
				source = rules->saddr;		/*源IP*/
				sport = rules->sport;		/*源端口*/
				dest = rules->daddr;		/*目的IP*/
				dport = rules->dport;		/*目的端口*/
				proto = rules->protocol;	/*协议类型*/
				chain = rules->chain;		/*链*/
				if(chain != chain_org)		/*链发生变化*/
				{
					chain_org = chain;		/*修改链*/
				
					printf("CHAIN %s Rules\n"	/*打印标题栏*/
						"ACTION"
						"\tSOURCE"
						"\tSPORT"
						"\tDEST"
						"\tDPORT"
						"\tPROTO"
						"\n",
						chain_name[chain_org]);
				}
				
				printf("%s"				/*打印信息*/
					"\t%s"
					"\t%ud"
					"\t%s"
					"\t%ud",
					"\t%d"
					"\n",
					action_name[i],		/*动作名称*/
					inet_ntoa(sip),			/*源IP地址*/
					sport,				/*源端口*/
					inet_ntoa(dip),		/*目的IP*/
					dport,				/*目的端口*/
					proto);				/*协议类型*/
			}
		}
	}
	else									/*其他命令类型*/
	{
		printf(" %s\n", retval?"Failure":"Success");
	}
	
	//printf(" Received message payload: %s\n",		NLMSG_DATA(nlmsgh));

	/* 关闭 Netlink套接字 */
	close(s);

	return 0;
}
#endif