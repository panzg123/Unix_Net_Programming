#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>

#include "locker.h"
#include "threadpool.h"
#include "server.h"

#define MAX_FD 100
#define MAX_EVENT_NUMBER 10000

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
#define ISspace(x) isspace((int)(x))
#define BUFFER_SIZE 1024
using namespace std;
char default_first_page[20];

/*
 *错误打印函数
 */
void error_die(const char *sc)
{
	perror(sc);
	exit(1);
}

/*
 * 配置监听套接字
*/
int startup(u_short *port) {
	int httpd = 0;
	struct sockaddr_in name;

	httpd = socket(PF_INET, SOCK_STREAM, 0);
	if (httpd == -1)
		error_die("socket");
	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(*port);
	name.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(httpd, (struct sockaddr *) &name, sizeof(name)) < 0)
		error_die("bind fault");
	if (*port == 0) /* if dynamically allocating a port */
	{
		socklen_t namelen = sizeof(name);
		if (getsockname(httpd, (struct sockaddr *) &name, &namelen) == -1)
			error_die("getsockname");
		*port = ntohs(name.sin_port);
	}
	if (listen(httpd, 5) < 0)
		error_die("listen");
	return (httpd);
}
int main() {

	int server_sock = -1;
	u_short port = 0;
	int client_sock = -1;
	struct sockaddr_in client_name;
	socklen_t client_name_len = sizeof(client_name);
	pthread_t newthread;
	char temp_buf[20];

	//构造线程池
	    threadpool< Server >* pool = NULL;
	    try
	    {
	        pool = new threadpool< Server >;
	    }
	    catch( ... )
	    {
	        return 1;
	    }

		//读取配置文件
	FILE *pweb_conf = fopen("./web_conf","r");
	if(pweb_conf == NULL)
		printf("无配置文件，采用默认配置\n");
	else
	{
		fscanf(pweb_conf,"%s %d\n",temp_buf,&port);
		fscanf(pweb_conf,"%s %s\n",temp_buf,default_first_page);
	}
	//启动监听端口
	server_sock = startup(&port);
	printf("Server running on port %d\n", port);

	while (1)
	{
		//处理请求
		client_sock = accept(server_sock, (struct sockaddr *) &client_name,
				&client_name_len);
		if (client_sock == -1)
			error_die("accept");
		printf("来自客户的连接请求：%d\n",client_sock);
		Server *new_user = new Server();
		new_user->m_sockfd = client_sock;
		strcpy(new_user->default_first_page,default_first_page);
		//加入线程池
		pool->append(new_user);
	/*	if (pthread_create(&newthread, NULL, accept_request, &client_sock) != 0)
			perror("pthread_create");*/
	}
	close(server_sock);

	return (0);
}
