#ifndef __KERNEL__
#define __KERNEL__
#endif /*__KERNEL__*/
#ifndef MODULE
#define MODULE
#endif /*MODULE*/
#include "sipfw.h"


#define MAX_COOKIE_LENGTH       PAGE_SIZE
static struct proc_dir_entry *sipfw_proc_dir;				/*PROC的目录*/
static struct proc_dir_entry *sipfw_proc_info;			/*防火墙的信息*/
static struct proc_dir_entry *sipfw_proc_defaultaction;	/*默认动作*/
static struct proc_dir_entry *sipfw_proc_logpause;		/*停止日志写入*/
static struct proc_dir_entry *sipfw_proc_invalid;			/*防火墙中止*/
static char *cookie_pot;  

/*防火墙信息读函数*/
int SIPFW_ProcInfoRead( 	char *buffer, 
					char **start, 
					off_t offset,
					int length, 
					int *eof, 
					void *data )
{
	int len;
	if (offset > 0) /*不分页*/
	{
		*eof = 1;
		return 0;
	}
	/*将信息传给用户空间用户*/
	len = sprintf(buffer, 		/*信息缓存*/
		"DefaultAction:%s\n"	/*默认动作*/
		"RulesFile:%s\n"		/*规则文件位置*/
		"LogFile:%s\n"		/*日志文件位置*/
		"RulesNumber:%d\n"	/*规则总个数*/
		"HitNumber:%d\n"		/*规则运行过程命中数*/
		"FireWall:%s\n",		/*防火墙是否终止*/
		(char*)sipfw_action_name[cf.DefaultAction].ptr,
		cf.RuleFilePath,
		cf.LogFilePath,
		sipfw_tables[0].number+sipfw_tables[1].number+sipfw_tables[2].number,
		cf.HitNumber,
		cf.Invalid?"INVALID":"VALID");
	return len;
}

int SIPFW_ProcLogRead( 	char *buffer, 
					char **start, 
					off_t offset,
					int length, 
					int *eof, 
					void *data )
{
	int len;
	if (offset > 0) 
	{
		*eof = 1;
		return 0;
	}
	/*将日志写入中止的设置给用户*/
	len = sprintf(buffer, "%d\n",cf.LogPause);
	return len;
}
ssize_t SIPFW_ProcLogWrite( struct file *filp, 
					const char __user *buff,
					unsigned long len, 
					void *data )
{
	/*将数据拷贝入缓冲区*/
	if (copy_from_user( cookie_pot, buff, len )) 
	{
		return -EFAULT;
	}
	/*格式获取输入值*/
	sscanf(cookie_pot,"%d\n",&cf.LogPause);

	return len;
}

int SIPFW_ProcActionRead( 	char *buffer, 
					char **start, 
					off_t offset,
					int length, 
					int *eof, 
					void *data )
{
	int len;
	if (offset > 0) 
	{
		*eof = 1;
		return 0;
	}
	/*默认工作的名称给用户*/
	len = sprintf(buffer, "%s\n",	(char*)sipfw_action_name[cf.DefaultAction].ptr);
	return len;
}
ssize_t SIPFW_ProcActionWrite( struct file *filp, 
					const char __user *buff,
					unsigned long len, 
					void *data )
{
	/*获取用户写入的数据*/
	if (copy_from_user( cookie_pot, buff, len )) 
	{
		return -EFAULT;
	}

	/*比较写入的字符串*/
	if(!strcmp(cookie_pot, "ACCEPT"))
	{
		cf.DefaultAction = SIPFW_ACTION_ACCEPT;
	}
	else if(!strcmp(cookie_pot, "DROP"))
	{
		cf.DefaultAction = SIPFW_ACTION_DROP;
	}

	return len;
}
int SIPFW_ProcInvalidRead( 	char *buffer, 
					char **start, 
					off_t offset,
					int length, 
					int *eof, 
					void *data )
{
	int len;
	if (offset > 0) 
	{
		*eof = 1;
		return 0;
	}
	len = sprintf(buffer, "%d\n",	cf.Invalid);
	return len;
}
ssize_t SIPFW_ProcInvalidWrite( struct file *filp, 
					const char __user *buff,
					unsigned long len, 
					void *data )
{
	if (copy_from_user( cookie_pot, buff, len )) 
	{
		return -EFAULT;
	}

	sscanf(cookie_pot,"%d\n",&cf.Invalid);

	return len;
}

/*PROC虚拟文件初始化函数*/
int SIPFW_Proc_Init( void )
{
	int ret = 0;
	/*申请内存保存用户写入的数据*/
	cookie_pot = (char *)vmalloc( MAX_COOKIE_LENGTH );
	if (!cookie_pot) /*申请失败*/
	{
		ret = -ENOMEM;
	} 
	else 
	{
		memset( cookie_pot, 0, MAX_COOKIE_LENGTH );/*清零缓冲区*/
		sipfw_proc_dir = proc_mkdir("sipfw",  proc_net);/*在/proc/net下建立sipfw目录*/
		sipfw_proc_info = create_proc_entry( "information", 0644, sipfw_proc_dir );/*信息项*/
		sipfw_proc_defaultaction = create_proc_entry( "defaultaction", 0644, sipfw_proc_dir );/*默认动作项*/
		sipfw_proc_logpause = create_proc_entry( "logpause", 0644, sipfw_proc_dir );/*日志中止项*/
		sipfw_proc_invalid= create_proc_entry( "invalid", 0644, sipfw_proc_dir );/*防火墙中止项*/
		if (sipfw_proc_info == NULL /*判断是否建立成功*/
			|| sipfw_proc_defaultaction == NULL 
			||sipfw_proc_logpause == NULL 
			||sipfw_proc_invalid == NULL) 
		{/*进行恢复工作*/
			ret = -ENOMEM;
			vfree(cookie_pot);
		} 
		else 
		{
			sipfw_proc_info->read_proc = SIPFW_ProcInfoRead;/*信息读函数*/
			sipfw_proc_info->owner = THIS_MODULE;

			sipfw_proc_defaultaction->read_proc = SIPFW_ProcActionRead;/*动作读函数*/
			sipfw_proc_defaultaction->write_proc= SIPFW_ProcActionWrite;/*动作写函数*/
			sipfw_proc_defaultaction->owner = THIS_MODULE;

			sipfw_proc_logpause->read_proc = SIPFW_ProcLogRead;/*日志读函数*/
			sipfw_proc_logpause->write_proc= SIPFW_ProcLogWrite;/*日志写函数*/
			sipfw_proc_logpause->owner = THIS_MODULE;

			sipfw_proc_invalid->read_proc = SIPFW_ProcInvalidRead;/*防火墙读函数*/
			sipfw_proc_invalid->write_proc= SIPFW_ProcInvalidWrite;/*防火墙写函数*/
			sipfw_proc_invalid->owner = THIS_MODULE;
		}
	}
	return ret;
}

/*PROC虚拟文件清理函数*/
void SIPFW_Proc_CleanUp( void )
{
	remove_proc_entry("defaultaction", sipfw_proc_dir);
	remove_proc_entry("logpause", sipfw_proc_dir);
	remove_proc_entry("invalid", sipfw_proc_dir);
	remove_proc_entry("information", sipfw_proc_dir);
	remove_proc_entry("sipfw", proc_net);
	
	vfree(cookie_pot);
}

