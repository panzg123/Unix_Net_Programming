#include "sipfw.h"
#include "sipfw_para.h"
union response
{
	char info_str[128];
	struct sipfw_rules rule;
	unsigned int count;
};
struct packet_u
{
	struct nlmsghdr nlmsgh;
	union response  payload;
};
struct packet_u message;
struct sockaddr_nl nlsource, nldest;		/*源地址和目标地址*/
int nls = -1;							/*套接字文件描述符*/


/*SIGINT信号截取函数*/
static void sig_int(int signo)
{
	DBGPRINT("==>sig_int\n");
	memset(&nldest, 0, sizeof(nldest));		/*目的地址*/
	nldest.nl_family = AF_NETLINK;			
	nldest.nl_pid    = 0;					/*内核*/
	nldest.nl_groups = 0;

	memset(&message, 0, sizeof(message));
	message.nlmsgh.nlmsg_len 	= NLMSG_LENGTH(0);	/*消息长度*/
	message.nlmsgh.nlmsg_flags 	= 0;
	message.nlmsgh.nlmsg_type 	= SIPFW_MSG_CLOSE;	/*关闭NL套接字*/
	message.nlmsgh.nlmsg_pid 	= getpid();			/*当前的PID*/

	/*将NL套接字关闭的消息发送给内核*/
	sendto(nls, &message, message.nlmsgh.nlmsg_len, 0, (struct sockaddr*)&nldest, sizeof(nldest));

	close(nls);
	DBGPRINT("<==sig_int\n");
	_exit(0);
}





/*显示命令类型*/
int SIPFW_DisplayOpts(struct sipfw_cmd_opts *opts)
{
	DBGPRINT("==>SIPFW_DisplayOpts\n");
	if(opts)
	{
		struct in_addr source, dest;
		source.s_addr = opts->source.v_uint;
		dest.s_addr = opts->dest.v_uint;
		DBGPRINT("SIPFW_CMD_LIST is %d\n",opts->command.v_uint);
		printf("command:%s\n", sipfw_command_name[opts->command.v_uint]);
		printf("source IP:%s\n",inet_ntoa(source));
		printf("Dest IP:%s\n",inet_ntoa(dest));
		printf("sport : %u\n",opts->sport.v_uint);
		printf("dport: %u\n",opts->dport.v_uint);
		printf("proto: %u\n",opts->protocol.v_uint);
		printf("ifname:%s\n",  opts->ifname.v_str);
	}
	DBGPRINT("<==SIPFW_DisplayOpts\n");
}

/*解析命令选项*/
static int SIPFW_ParseOpt(int opt, char *str, union sipfw_variant *var)
{
	const struct vec *p = NULL;
	int chain = SIPFW_CHAIN_ALL;
	int action = SIPFW_ACTION_DROP;
	unsigned int port = 0,ip = 0;
	int protocol = 0, i = 0;

	DBGPRINT("==>SIPFW_ParseOpt\n");
	switch(opt)
	{
		case SIPFW_OPT_CHAIN:/*链名称*/
			if(str){				
				for(i = 0;i<SIPFW_CHAIN_NUM;i++){/*遍历链查找匹配项*/
					if(!strncmp(str, sipfw_chain_name[i].ptr, sipfw_chain_name[i].len)){
						chain = i;
						break;
					}
				}
			}
			var->v_uint = chain;
			break;
		case SIPFW_OPT_ACTION:/*动作名称匹配*/
			if(str)	{				
				for(i = 0;i<SIPFW_ACTION_NUM;i++){/*查找动作名称并匹配*/				
					if(!strncmp(str, sipfw_action_name[i].ptr, sipfw_action_name[i].len))	{
						action = i;
						break;
					}
				}
			}
			var->v_uint = action;
			break;
		case SIPFW_OPT_IP:/*将字符串转为网络字节序*/
			if(str)
				ip = inet_addr(str);

			var->v_uint = ip;
			break;
			
		case SIPFW_OPT_PORT:/*将字符串类型转为网络序*/
			if(str){
				port = htons(strtoul(str, NULL, 10));
			}
			var->v_uint = port;
			break;
			
		case SIPFW_OPT_PROTOCOL:/*将协议的名称转为值*/
			if(str){
				for(p=sipfw_protocol_name + 0; p->ptr != NULL; p++){
					if(!strncmp(p->ptr, str, p->len)){
						protocol = p->value;
						break;
					}
				}
			}
			var->v_uint = protocol;
			break;
			
		case SIPFW_OPT_STR:/*字符串直接拷贝*/
			if(str){
				int 	len = strlen(str);
				memset(var->v_str, 0, sizeof(var->v_str));
				if(len < 8){
					memcpy(var->v_str, str, len);

				}
			}
			break;

		default:
			break;
	}
	DBGPRINT("<==SIPFW_ParseOpt\n");
}

static int 
SIPFW_ParseCommand(int argc, char *argv[], 	struct sipfw_cmd_opts *cmd_opt)
{
	DBGPRINT("==>SIPFW_ParseCommand\n");
	struct option longopts[] = 
	{						/*长选项*/
		{"source",	required_argument, 	NULL,	's'},	/*源主机IP地址*/
		{"dest",        	required_argument, 	NULL,	'd'},	/*目的主机IP地址*/
		{"sport",        	required_argument, 	NULL,	'm'},	/*源端口地址*/
		{"dport",       	required_argument, 	NULL,	'n'},	/*目的端口地址*/
		{"protocol", 	required_argument, 	NULL,	'p'},	/*协议类型*/
		{"list",    		optional_argument, 	NULL,	'L'},	/*规则列表*/
		{"flush",        	optional_argument, 	NULL,	'F'},	/*清空规则*/
		{"append", 	required_argument, 	NULL,	'A'},	/*增加规则到链尾部*/
		{"insert",     	required_argument, 	NULL,	'I'},	/*向链中增加规则*/
		{"delete",  	required_argument, 	NULL,	'D'},	/*删除规则*/
		{"interface",  	required_argument, 	NULL,	'i'},	/*网络接口*/
		{"action",  	required_argument, 	NULL,	'j'},	/*动作*/
		{"syn",  		no_argument, 		NULL,	'y'},	/*syn*/
		{"rst",  		no_argument, 		NULL,	'r'},	/*rst*/
		{"acksyn",  	no_argument, 		NULL,	'k'},	/*acksyn*/
		{"fin",  		no_argument, 		NULL,	'f'},	/*fin*/
		{"number",	required_argument,	NULL,	'u'},	/*删除或者插入的位置*/
		{0, 0, 0, 0},
	};
	static char opts_short[] =  "s:d:m:n:p:LFA:I:D:i:j:yrkfu:";	/*短选项*/

	static char *l_opt_arg = NULL;/*产选项的参数*/
	
	cmd_opt->command.v_int = -1;	/*命令默认值为-1*/
	cmd_opt->source.v_int = 0;		/*源地址默认值为0*/
	cmd_opt->sport.v_int = 0;			/*源端口默认值为0*/
	cmd_opt->dest.v_int =0;			/*目的地址默认值为0*/
	cmd_opt->dport.v_int = 0;			/*目的端口默认值为0*/
	cmd_opt->protocol.v_int = -1;		/*协议类型默认值为-1*/
	cmd_opt->chain.v_int = -1;		/*链默认值为-1*/
	cmd_opt->action.v_int= -1;		/*动作默认值为-1*/
	memset(cmd_opt->ifname.v_str, 0, 8);
	
		
	char c = 0;
	while ((c = getopt_long(argc, argv, opts_short,  longopts, NULL)) != -1) 
	{
		switch(c)
		{
			case 's':		/*源主机IP地址*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_IP, optarg, &cmd_opt->source);
				}
				
				break;
			case 'd':/*目的主机IP地址*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_IP, optarg, &cmd_opt->dest);
				}
				
				break;
			case 'm':/*源端口地址*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_PORT, optarg, &cmd_opt->sport);
				}
				
				break;
			case 'n':/*目的端口地址*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_PORT, optarg, &cmd_opt->dport);
				}
				
				break;
			case 'p':/*协议类型*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_PROTOCOL, optarg, &cmd_opt->protocol);
				}
				
				break;
			case 'L':/*规则列表*/
				cmd_opt->command.v_uint = SIPFW_CMD_LIST;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				break;
				
			case 'F':/*清空规则*/
				cmd_opt->command.v_uint = SIPFW_CMD_FLUSH;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
				break;
			case 'A':/*增加规则到链尾部*/
				cmd_opt->command.v_uint = SIPFW_CMD_APPEND;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
				break;
			case 'I':/*向链中增加规则*/
				cmd_opt->command.v_uint = SIPFW_CMD_INSERT;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
				break;
			case 'D':/*删除规则*/
				cmd_opt->command.v_uint = SIPFW_CMD_DELETE;
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_CHAIN, optarg, &cmd_opt->chain);
				}
				
				break;
			case 'i':/*网络接口*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_STR, optarg, &cmd_opt->ifname);
				}
				break;
			case 'j':/*动作*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_ACTION, optarg, &cmd_opt->action);
				}
				break;
			case 'y':/*syn*/
				cmd_opt->addtion.tcp.valid = 1;
				cmd_opt->addtion.tcp.syn = 1;
				break;
			case 'r':/*rst*/
				cmd_opt->addtion.tcp.valid = 1;
				cmd_opt->addtion.tcp.rst= 1;
				break;
			case 'k':/*acksyn*/
				cmd_opt->addtion.tcp.valid = 1;
				cmd_opt->addtion.tcp.ack= 1;
				cmd_opt->addtion.tcp.syn= 1;
				break;
			case 'f':/*fin*/
				cmd_opt->addtion.tcp.valid = 1;
				cmd_opt->addtion.tcp.fin= 1;
				break;
			case 'u':/*number*/
				l_opt_arg = optarg;
				if(l_opt_arg && l_opt_arg[0]!=':')
				{
					SIPFW_ParseOpt(SIPFW_OPT_PORT, optarg, &cmd_opt->number);
				}
				break;
			default:
				break;
		}
	}

	DBGPRINT("<==SIPFW_ParseCommand\n");
}

static int SIPFW_NLCreate(void)
{
	DBGPRINT("==>SIPFW_NLCreate\n");
	int err = -1;
	int retval = -1;
	nls = socket(PF_NETLINK, 				/*建立套接字*/
				SOCK_RAW, NL_SIPFW);
	if(nls < 0)/*失败*/
	{
		DBGPRINT("can not create a netlink socket\n");
		retval = -1;
		goto EXITSIPFW_NLCreate;
	}

	/*设置源地址*/
	memset(&nlsource, 0, sizeof(nlsource));		/*清空缓冲区*/
	nlsource.nl_family 	= AF_NETLINK;		/*协议族*/
	nlsource.nl_pid 		= getpid();  			/*本进程ID*/
	nlsource.nl_groups 	= 0;  				/*单播*/

	err = bind(nls, 							/*绑定*/
		(struct sockaddr*)&nlsource, sizeof(nlsource));
	if(err == -1)
	{
		retval = -1;
		goto EXITSIPFW_NLCreate;
	}

EXITSIPFW_NLCreate:
	DBGPRINT("<==SIPFW_NLCreate\n");
	return retval;
}

static ssize_t SIPFW_NLSend(char *buf, int len, int type)
{
	DBGPRINT("==>SIPFW_NLSend\n");
	ssize_t size = -1;
	memset(&nldest, 0, sizeof(nldest));			/*清空缓冲区*/
	nldest.nl_family 	= AF_NETLINK;		/*协议族*/
	nldest.nl_pid 		= 0;   				/*发送给内核*/
	nldest.nl_groups 	= 0; 				/*单播*/

	/* 填充netlink消息头*/
	message.nlmsgh.nlmsg_len 	= NLMSG_LENGTH(len);/*长度*/
	message.nlmsgh.nlmsg_pid 	= getpid();  		/*本进程的PID*/
	message.nlmsgh.nlmsg_flags 	= 0;				/*标志*/
	message.nlmsgh.nlmsg_type	= type;			/*类型*/
	/* 填充netlink消息的负载*/
	memcpy(NLMSG_DATA(&message.nlmsgh), buf, len);
	/*发送给内核*/
	size = sendto(nls,&message, message.nlmsgh.nlmsg_len, 0, (struct sockaddr*)&nldest, sizeof(nldest));

	DBGPRINT("<==SIPFW_NLSend\n");
	return size;
}

static ssize_t SIPFW_NLRecv(void)
{
	DBGPRINT("==>SIPFW_NLRecv\n");
	/* 从内核接收消息 */
	int len = sizeof(nldest);
	char *info = NULL;
	ssize_t size = -1;
	
	memset(&nldest, 0, sizeof(nldest));
	nldest.nl_family = AF_NETLINK;
	nldest.nl_pid    = 0;				/*从内核接收*/
	nldest.nl_groups = 0;
	
	size = recvfrom(nls, /*接收消息*/
			&message, 
			sizeof(message), 
			0, 
			(struct sockaddr*)&nldest, 
			&len);					
	DBGPRINT("<==SIPFW_NLRecv\n");
	return size;
}

static void SIPFW_NLClose(void)
{
	DBGPRINT("==>SIPFW_NLClose\n");
	close(nls);
	DBGPRINT("<==SIPFW_NLClose\n");
}

/*接收并显示规则,规则列表每次仅仅发送一个
*	count为规则的个数
*/
static ssize_t SIPFW_NLRecvRuleList(unsigned int count)
{
	DBGPRINT("==>SIPFW_NLRecvRuleList\n");
	int i = -1;
	int size = -1;
	unsigned int sip = 0, dip = 0;		/*原IP地址和目的IP地址*/
	unsigned short sport = 0, dport = 0;	/*源端口和目的端口*/
	unsigned char proto = 0;			/*协议类型*/
	int action = 0;			/*动作类型*/
	unsigned char chain_org = SIPFW_CHAIN_NUM, chain;
	struct sipfw_rules *rules = NULL;
	struct in_addr source, dest;
	

	for(i=0; i< count; i++)
	{
		size = SIPFW_NLRecv();		/*接收内核发送的数据*/
		if(size < 0)
		{
			continue;
		}
		
		rules = &message.payload.rule;
		action = rules->action;		/*动作*/
		source.s_addr = rules->source;/*源IP*/
		sport = ntohs(rules->sport);		/*源端口*/
		dest.s_addr = rules->dest;	/*目的IP*/
		dport = ntohs(rules->dport);		/*目的端口*/
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
				"\t\tDPORT"
				"\tPROTO"
				"\n",
				sipfw_chain_name[chain_org]);
		}

		if((action>-1 && action <3))/*动作名称*/
			printf("%s", sipfw_action_name[action]);
		else
			printf("%s", "NOTSET");
		printf("\t%s", inet_ntoa(source));/*源IP地址*/
		printf("\t%d", sport);/*源端口*/
		printf("\t%s", inet_ntoa(dest));/*目的IP*/
		printf("\t%d", dport);/*目的端口*/
		printf("\t%d\n", proto);/*协议类型*/
		

	}
	DBGPRINT("<==SIPFW_NLRecvRuleList\n");
}

static int 
SIPFW_JudgeCommand(struct sipfw_cmd_opts *opts)
{
	int retval = 0;
	switch(opts->command.v_int)
	{
		case SIPFW_CMD_APPEND:
			if(opts->chain.v_int>SIPFW_CHAIN_NUM 
				|| opts->chain.v_int< 0
				|| opts->action.v_int == -1)
				retval = -1;
			break;
		case SIPFW_CMD_DELETE:
			if(opts->chain.v_int>SIPFW_CHAIN_NUM 
				|| opts->chain.v_int< 0)
				retval = -1;
			break;
		case SIPFW_CMD_FLUSH:
			if(opts->chain.v_int == -1)
				opts->chain.v_int = SIPFW_CHAIN_ALL;
			
			if(opts->chain.v_int>SIPFW_CHAIN_NUM 
				|| opts->chain.v_int< 0)
				retval = -1;
			break;
		case SIPFW_CMD_INSERT:
			if(opts->chain.v_int>=SIPFW_CHAIN_NUM 
				|| opts->chain.v_int< 0
				|| opts->number.v_int == -1)
			break;
		case SIPFW_CMD_LIST:
			if(opts->chain.v_int == -1)
				opts->chain.v_int = SIPFW_CHAIN_ALL;
			if(opts->chain.v_int>SIPFW_CHAIN_NUM 
				|| opts->chain.v_int< 0)
				retval = -1;
			break;
		case SIPFW_CMD_REPLACE:
			if(opts->chain.v_int>=SIPFW_CHAIN_NUM 
				|| opts->chain.v_int< 0
				|| opts->number.v_int == -1)
				retval = -1;
			break;
		default:
			retval = -1;
			break;		
	}

	return retval;
}
int main(int argc, char *argv[]) 
{

	int err = -1;
	char *msg = "test";
	struct sipfw_cmd_opts cmd_opt;
	ssize_t size ;

	signal(SIGINT, sig_int);				/*挂接中断信号*/
	cmd_opt.action.v_int = -1;
	cmd_opt.addtion.valid = 0;
	cmd_opt.chain.v_int  = -1;
	cmd_opt.command.v_int = -1;
	cmd_opt.dest.v_uint = 0;
	cmd_opt.dport.v_int = -1;
	cmd_opt.protocol.v_int = -1;
	cmd_opt.number.v_int = -1;
	cmd_opt.source.v_uint = 0;
	cmd_opt.sport.v_int = -1;

	SIPFW_ParseCommand(argc, argv, &cmd_opt);	/*解析命令格式*/
	if(SIPFW_JudgeCommand(&cmd_opt))
		return -1;
	SIPFW_DisplayOpts(&cmd_opt);				/*显示解析结果*/
	SIPFW_NLCreate();							/*建立NetLink套接字*/
	
	size = SIPFW_NLSend((char*)&cmd_opt, sizeof(cmd_opt), SIPFW_MSG_PID);/*发送命令*/
	if(size < 0){									/*失败*/	
		return -1;
	}

	size = SIPFW_NLRecv();						/*接收内核响应*/
	if(size < 0){									/*失败*/	
		return -1;
	}
	
	if(cmd_opt.command.v_uint == SIPFW_CMD_LIST){	/*获得规则列表*/		
		unsigned int count  = 0;					/*规则列表的数据量*/
		
		if(size > 0){
			count = message.payload.count;			/*规则个数*/
		}	else		{
			return -1;
		}
		SIPFW_NLRecvRuleList(count);				/*接收并显示规则*/
	}else{
		DBGPRINT("information:%s\n",message.payload.info_str);
	}	
	
	SIPFW_NLClose();							/*关闭NetLink套接字*/

	return 0;
}


