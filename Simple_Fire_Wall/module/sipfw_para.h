#ifndef __SIPFW_PARA_H__
#define __SIPFW_PARA_H__
const vec sipfw_chain_name[] = {		/*链的名称*/
	{"INPUT",	5,0},					/*INPUT链*/
	{"OUTPUT",	6,0},					/*OUTPUT链*/
	{"FORWARD",	7,0},					/*FORWARD链*/
	{NULL,		0,0}  };				/*结尾*/

const vec sipfw_action_name[] = {		/*动作名称*/

	{"DROP",	4,0},						/*DROP动作*/
	{"ACCEPT",	6,0},					/*ACCEPT动作*/
	{"STOLEN",	6,0},					/*STOLEN动作*/
	{"QUEUE",	6,0},					/*QUEUE动作*/
	{"REPEAT",	6,0},					/*REPEAT动作*/
	
	{NULL,		0,0}  };				/*结尾*/
const vec sipfw_command_name[] = {	/*命令名称*/
	{"INSERT",	6,0},					/*插入*/
	{"DELETE",	6,0},					/*删除*/
	{"APPEND",	6,0},					/*尾部增加*/
	{"LIST",	4,0},						/*列表规则*/
	{"FLUSH",	5,0},					/*清空规则*/
	{NULL,		0,0}  };				/*结尾*/

const vec sipfw_protocol_name[] = {	/*协议类型名称*/
	{"tcp",	3,IPPROTO_TCP},						/*TCP协议*/
	{"udp",	3,IPPROTO_UDP},						/*UDP协议*/
	{"icmp",	4,IPPROTO_ICMP},						/*ICMP协议*/
	{"igmp",	4,IPPROTO_IGMP},						/*IGMP*/
	{NULL,		0,0}  };				/*结尾*/
	
#ifdef __KERNEL__
struct sipfw_conf cf={SIPFW_ACTION_ACCEPT, "/etc/sipfw.rules","/etc/sipfw.log",0,0,0};
struct sipfw_list sipfw_tables[SIPFW_CHAIN_NUM] ;
#endif /*__KERNEL__*/
#endif /*__SIPFW_PARA_H__*/
