/*
 * server.h
 *
 *  Created on: 2015-4-24
 *      Author: panzg
 */

#ifndef SERVER_H_
#define SERVER_H_

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/stat.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <sys/wait.h>
#include "locker.h"

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
#define ISspace(x) isspace((int)(x))
#define BUFFER_SIZE 1024
using namespace std;

class Server
{
public :
	char default_first_page[20];   //配置的首页
	int m_sockfd;  //文件描述符

public:
	Server(){}
	~Server(){}
public:
	void accept_request();                                      //请求处理入口函数
	void unimplemented(int);                                //未实现的方法
	void error_die(const char *);                           //错误打印函数
	int get_line(int sock,char *buf,int size);            //从socket中读取一行信息
	void not_found(int client);                                //文件不存在，404
	void headers(int,const char*);                       //响应头
	void cat(int,FILE*);                                           //发送文件信息
	void page_cat(int,FILE*);                                  //改进版本，文件读取函数
	void serve_file(int,const char*);                     //处理 静态资源 请求
	void exec_get_cgi(int client, const char *path, const char *method,const char *query_string); //执行cgi脚本
	void cannot_execute(int client);                     //不能执行cgi脚本，错误
};


#endif /* SERVER_H_ */
