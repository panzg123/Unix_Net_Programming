#ifndef __KERNEL__
#define __KERNEL__
#endif /*__KERNEL__*/
#ifndef MODULE
#define MODULE
#endif /*MODULE*/
#include "sipfw.h"

/*打开文件*/
struct file *SIPFW_OpenFile(const char *filename, int flags, int mode)
{
	struct file *f = NULL;

	DBGPRINT("==>SIPFW_OpenFile\n");

	f = filp_open(filename, flags, 0);	/*filp_open打开文件*/
	if (!f || IS_ERR(f))				/*判断错误*/
	{
		f = NULL;
	}

	DBGPRINT("<==SIPFW_OpenFile\n");
	return f;
}


/*从文件中读取一行，最多为len字节，放到buf中*/
ssize_t SIPFW_ReadLine(struct file *f, char *buf, size_t len)
{
#define EOF (-1)/*文件结束*/

	ssize_t count = -1;
	mm_segment_t oldfs;/*老的地址空间设置方式*/
	struct inode *inode;/*节点*/
	DBGPRINT("==>SIPFW_ReadLine\n");

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
	/*文件节点*/
	inode = f->f_dentry->d_inode;

	/*判断文件权限是否可读*/
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
			DBGPRINT("file read failure\n");
			goto out;
		}

		if (*buf == EOF)			/*文件结束*/
		{
			DBGPRINT("file EOF\n");
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
	DBGPRINT("<==SIPFW_ReadLine\n");
	return count;
}

/*向文件中写入一行*/
ssize_t SIPFW_WriteLine(struct file *f, char *buf, size_t len)
{
	ssize_t count = -1;
	mm_segment_t oldfs;
	struct inode *inode;
	DBGPRINT("==>SIPFW_WriteLine\n");

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
		//f->f_pos = f->f_count;
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
	DBGPRINT("<==SIPFW_WriteLine\n");
	return count;
}

/*关闭文件*/
void SIPFW_CloseFile(struct file *f)
{
	DBGPRINT("==>SIPFW_CloseFile\n");
	if(!f)
		return;
	
	filp_close(f, current->files);
	DBGPRINT("<==SIPFW_CloseFile\n");
}

/*将命中网络数据信息写入日志文件，格式为
*from [IP:port] to [IP:port] protocol [string] was [Action name]
*/
int SIPFW_LogAppend(struct sk_buff *skb, struct sipfw_rules *r)
{
	char buff[2048];		/*保存写入文件的数据*/
	struct file *f;			/*日志文件*/
	int retval = 0;		/*返回值*/
	struct tm cur;		/*当前日期指针*/
	unsigned long time;	/*当前的描述*/
	const struct vec *proto;/*协议向量*/
	struct iphdr *iph = skb->nh.iph;/*网络数据的IP头部*/

	if(cf.LogPause)		/*暂停向日志中写入文件*/
	{
		retval = -1;		/*返回*/
		goto EXITSIPFW_LogAppend;
	}

	/*打开日志文件*/
	f = SIPFW_OpenFile(cf.LogFilePath, O_CREAT|O_RDWR|O_APPEND, 0);
	if(f == NULL)
	{
		retval = -1;
		goto EXITSIPFW_LogAppend;
	}
	time = get_seconds();		/*获得当前时间*/
	SIPFW_Localtime(&cur, time);/*转变为可理解数据*/

	/*查找协议名称*/
	for(proto = &sipfw_protocol_name[0];
		proto->ptr != NULL && proto->value != iph->protocol;
		proto++)
		;

	/*构造写入日志文件的数据信息*/
	snprintf(buff, 						/*信息缓冲区*/
		2048,							/*缓冲区长度*/
		"Time: %04d-%02d-%02d "			/*日期的年月日*/
		"%02d:%02d:%02d  "				/*日期的时分秒*/
		"From %d.%d.%d.%d "				/*来源IP*/
		"To %d.%d.%d.%d "				/*目的IP*/
		" %s PROTOCOL "					/*协议类型*/
		"was %sed\n",					/*处理方式动作*/
		cur.year,	cur.mon, cur.mday,		/*年月日*/
		cur.hour,  cur.min,  cur.sec,			/*时分秒*/
		(iph->saddr & 0x000000FF)>>0,		/*源地址第一段*/
		(iph->saddr & 0x0000FF00)>>8,		/*源地址第二段*/
		(iph->saddr & 0x00FF0000)>>16,	/*源地址第三段*/
		(iph->saddr & 0xFF000000)>>24,	/*源地址第四段*/
		(iph->daddr & 0x000000FF)>>0,		/*目的地址第一段*/
		(iph->daddr & 0x0000FF00)>>8,		/*目的地址第二段*/
		(iph->daddr & 0x00FF0000)>>16,	/*目的地址第三段*/
		(iph->daddr & 0xFF000000)>>24,	/*目的地址第四段*/
		(char*)proto->ptr,					/*协议名称*/
		(char*)sipfw_action_name[r->action].ptr);/*动作名称*/
	SIPFW_WriteLine(f, buff, strlen(buff));	/*写入文件*/
	SIPFW_CloseFile( f);					/*关闭文件*/
	
EXITSIPFW_LogAppend:
	return retval;	
}

/*从配置文件中读取配置信息*/
int SIPFW_HandleConf(void)
{
	int retval = 0,count;
	char *pos = NULL;
	struct file *f = NULL;
	char line[256];
	DBGPRINT("==>SIPFW_HandleConf\n");
	f = SIPFW_OpenFile("/etc/sipfw.conf", /*打开文件*/
				O_CREAT|O_RDWR|O_APPEND, 0);
	if(f == NULL)/*失败*/
	{
		retval = -1;
		goto EXITSIPFW_HandleConf;
	}	

	while((count = SIPFW_ReadLine(f, line, 256))>0)/*读取一行*/
	{
		pos = line;							/*数据头*/
		
		if(!strncmp(pos, "DefaultAction",13))		/*默认动作?*/
		{
			pos += 13+1;						/*更改位置*/
			if(!strncmp(pos, "ACCEPT",6))		/*是否ACCEPT*/
			{
				cf.DefaultAction = SIPFW_ACTION_ACCEPT;
			}
			else if(!strncmp(pos, "DROP",4))	/*是否DROP*/
			{
				cf.DefaultAction = SIPFW_ACTION_DROP;
			}
		}
		else if(!strncmp(pos, "RulesFile",9))		/*规则文件路径*/
		{
			pos += 10;
			strcpy(cf.RuleFilePath, pos);		/*拷贝*/
		}
		else if(!strncmp(pos, "LogFile",7))		/*日志文件路径*/
		{
			pos += 8;
			strcpy(cf.LogFilePath,pos );			/*拷贝*/
		}
	}
	SIPFW_CloseFile(f);						/*关闭文件*/
EXITSIPFW_HandleConf:
	DBGPRINT("<==SIPFW_HandleConf\n");
	return retval;
}




