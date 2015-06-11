#ifndef __SIPFW_H__
#define __SIPFW_H__

#define SIPFW_DEBUG
#ifdef __KERNEL__
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
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#ifdef SIPFW_DEBUG
#define DBGPRINT printk
#else /*SIPFW_DEBUG*/
#define DBGPRINT
#endif /*SIPFW_DEBUG*/
struct sipfw_conf {

	/* server configuration */
	__u32	DefaultAction;
	__u8	RuleFilePath[256];
	__u8	LogFilePath[256];
	int		HitNumber;
	int		Invalid;
	int		LogPause;
};
struct tm 
{
	int sec;         /* seconds */
	int min;         /* minutes */
	int hour;        /* hours */
	int mday;        /* day of the month */
	int mon;         /* month */
	int year;        /* year */
};


#else /*__KERNEL__*/

#include <unistd.h>
#include <stdio.h>
#include <linux/types.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <signal.h>
#include <getopt.h>
#ifdef SIPFW_DEBUG
#define DBGPRINT printf
#else /*SIPFW_DEBUG*/
#define DBGPRINT
#endif /*SIPFW_DEBUG*/

#endif /*__KERNEL__*/

#define SIPFW_MSG_PID		0
#define SIPFW_MSG_RULE		1
#define SIPFW_MSG_CLOSE	2
#define SIPFW_MSG_FAILURE	3
#define SIPFW_MSG_SUCCESS	4
#define NL_SIPFW      31
struct icgmp_flag		/*ICMP/IGMP*/
{
	__u8	valid;		/*有效*/
	__u8	type;		/*类型*/
	__u8	code;		/*代码*/
};

struct tcp_flag			/*TCP选项*/
{
	__u16	res1:4,
			doff:4,
			fin:1,
			syn:1,
			rst:1,
			psh:1,
			ack:1,
			urg:1,
			ece:1,
			cwr:1;
	__u8	valid;		/*有效*/
};

union addtion				/*附加项*/
{
	__u32 			valid;
	struct icgmp_flag 	icgmp;
	struct tcp_flag	tcp;
};
struct sipfw_rules{
	int		chain;				/*链*/
	__be32	source;				/*源地址*/
	__be32	dest;				/*目的地址*/

	__be16	sport;				/*源端口*/
	__be16	dport;				/*目的端口*/
	__u8	protocol;			/*协议类型*/
	int		action;				/*动作*/
	__u8	ifname[8];			/*网络接口*/
	union addtion addtion;
#ifdef __KERNEL__
	struct sipfw_rules* next;		/*下一个*/
#endif
};

enum{
	SIPFW_CMD_INSERT 		= 0,		/*向规则链中插入新规则*/
	SIPFW_CMD_DELETE ,			/*从规则链中删除某规则*/
	SIPFW_CMD_APPEND,			/*将新规则加到规则链末尾*/
	SIPFW_CMD_LIST,				/*列出规则链中的规则*/
	SIPFW_CMD_FLUSH,				/*清空规则*/
	SIPFW_CMD_REPLACE,			/*更换某个规则*/
	SIPFW_CMD_NUM 	= 6,			/*命令的个数*/

	SIPFW_ACTION_DROP = 0,		/*NF_DROP*/
	SIPFW_ACTION_ACCEPT = 1,		/*NF_ACCEPT*/
	SIPFW_ACTION_STOLEN = 2,		/*NF_STOLEN*/
	SIPFW_ACTION_QUEUE = 3,		/*NF_QUEUE*/
	SIPFW_ACTION_REPEAT = 4,		/*NF_REPEAT*/
	SIPFW_ACTION_STOP = 5,		/*NF_STOP*/
	
	
	SIPFW_ACTION_NUM = 2,

	SIPFW_CHAIN_INPUT = 0,			/*INPUT链*/
	SIPFW_CHAIN_OUTPUT,			/*OUTPUT链*/
	SIPFW_CHAIN_FORWARD,			/*转发链*/
	SIPFW_CHAIN_NUM,
	SIPFW_CHAIN_ALL=3,				/*所有链*/

	SIPFW_OPT_CHAIN,				/*链选项*/
	SIPFW_OPT_IP,					/*IP选项*/
	SIPFW_OPT_PORT,				/*端口选项*/
	SIPFW_OPT_PROTOCOL,			/*协议选项*/
	SIPFW_OPT_STR,					/*字符串选项*/
	SIPFW_OPT_ACTION				/*动作选项*/
};

typedef struct vec {					/*向量结构定义*/
	void *ptr;						/*字符串*/
	unsigned long len;					/*长度*/
	int	value;
}vec;

union sipfw_variant {				/*变量枚举类型*/
	char			v_str[8];			/*字符串*/
	int			v_int;				/*符号整型*/
	unsigned int	v_uint;				/*无符号整型*/
	time_t		v_time;				/*时间类型*/
	struct vec	v_vec;				/*向量类型*/
};
struct sipfw_cmd_opts {
	union sipfw_variant	command;	/*命令*/
	union sipfw_variant	source;		/*源地址*/
	union sipfw_variant	dest;		/*目的地址*/
	union sipfw_variant	sport;		/*源端口*/
	union sipfw_variant	dport;		/*目的端口*/
	union sipfw_variant	protocol;	/*协议类型*/
	union sipfw_variant	chain;		/*链*/
	union sipfw_variant	ifname;		/*网络接口*/
	union sipfw_variant	action;		/*动作*/
	union addtion 		addtion;		/*附件项*/
	union sipfw_variant	number;		/*增加或者删除的序号*/
};

	
#ifdef __KERNEL__

struct sipfw_list
{
	struct sipfw_rules		*rule;
	rwlock_t 				lock;
	int 					number;
};
extern struct sipfw_conf cf;
extern struct sipfw_list sipfw_tables[];
extern const vec sipfw_protocol_name[];
extern const vec sipfw_command_name[] ;
extern const vec sipfw_chain_name[] ;
extern const vec sipfw_action_name[] ;
extern struct file *SIPFW_OpenFile(const char *filename, int flags, int mode);
extern ssize_t SIPFW_ReadLine(struct file *f, char *buf, size_t len);
extern ssize_t SIPFW_WriteLine(struct file *f, char *buf, size_t len);
extern void SIPFW_CloseFile(struct file *f);
extern int SIPFW_LogAppend(struct sk_buff *skb, struct sipfw_rules *r);
int SIPFW_HandleConf(void);


extern int SIPFW_Proc_Init( void );
extern void SIPFW_Proc_CleanUp( void );

extern struct sipfw_rules * SIPFW_IsMatch(struct sk_buff *skb,struct sipfw_rules *l);
extern void SIPFW_Localtime(struct tm *r, unsigned long time);

extern int SIPFW_ListDestroy(void);
extern int SIPFW_NLCreate(void);
extern int SIPFW_NLDestory(void);




#else /*__KERNEL__*/

#endif /*__KERNEL__*/


#endif
