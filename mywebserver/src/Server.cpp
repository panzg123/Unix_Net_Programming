/*
 * Server.cpp
 *
 *  Created on: 2015-4-24
 *      Author: panzg
 */
#include "server.h"

// 请求处理 入口函数
void Server::accept_request()
{
	int client = m_sockfd;
    char buf[BUFFER_SIZE];
    int numchars;
    	char method[255];
    	char url[255];
    	char path[512];
    	size_t i, j;
    	struct stat st;
    	int cgi = 0; /* 标志为cgi, 1表示带参数get或者post，0为静态资源的请求 */
    		char *query_string = NULL;
    		numchars = get_line(client, buf, sizeof(buf));
    		printf("%s\n",buf); /*查看状态行*/
    		i = 0;
    		j = 0;
    		while (!ISspace(buf[j]) && (i < sizeof(method) - 1)) {
    			method[i] = buf[j];
    			i++;
    			j++;
    		}
    		method[i] = '\0';

    		if (strcasecmp(method, "GET") && strcasecmp(method, "POST")) {
    			unimplemented(client);
    			return;
    		}

    		if (strcasecmp(method, "POST") == 0)
    			cgi = 1;

    		i = 0;
    		while (ISspace(buf[j]) && (j < sizeof(buf)))
    			j++;
    		while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf))) {
    			url[i] = buf[j];
    			i++;
    			j++;
    		}
    		url[i] = '\0';

    		//带参数的get请求
    		if (strcasecmp(method, "GET") == 0) {
    			query_string = url;
    			while ((*query_string != '?') && (*query_string != '\0'))
    				query_string++;
    			if (*query_string == '?') {
    				cgi = 1;
    				*query_string = '\0';
    				query_string++;
    			}
    		}

    		sprintf(path, "htdocs%s", url);
    		if (path[strlen(path) - 1] == '/')   //没有指定网页
    			strcat(path, default_first_page);
    		if (stat(path, &st) == -1)
    		{
    			while ((numchars > 0) && strcmp("\n", buf)) /* read & discard headers */
    				numchars = get_line(client, buf, sizeof(buf));
    			not_found(client);
    		}
    		else
    		{
    			if ((st.st_mode & S_IFMT) == S_IFDIR)   //目录
    				{
    				    strcat(path, "/");
    				    strcat(path, default_first_page);
    				}
    			if ((st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP)
    					|| (st.st_mode & S_IXOTH))
    				cgi = 1;
    			if (!cgi)     //get 静态资源
    				serve_file(client, path);
    			else
    			{
    				//execute_cgi(client, path, method, query_string);
    				if(strcasecmp(method, "GET") == 0)   //get 带参数
    					exec_get_cgi(client,path,method,query_string);
    				else  //post或者其他请求
    					{
           					printf(" path:%s\n method:%s\n query_string:%s\n",path,method,query_string);
    					     unimplemented(client);
    					}
    			}
    		}
    		printf("处理请求成功！\n");
    		close(client);
}

//错误打印函数
void Server::error_die(const char *sc)
{
	perror(sc);
	exit(1);
}

//post等尚未实现的处理
void Server::unimplemented(int client)
{
	char buf[1024];

	sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-Type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "</TITLE></HEAD>\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "</BODY></HTML>\r\n");
	send(client, buf, strlen(buf), 0);
}

//从socket中读取一行数据
int Server::get_line(int sock, char *buf, int size) {
	int i = 0;
	char c = '\0';
	int n;

	while ((i < size - 1) && (c != '\n')) {
		n = recv(sock, &c, 1, 0);
		/* DEBUG printf("%02X\n", c); */
		if (n > 0) {
			if (c == '\r') {
				n = recv(sock, &c, 1, MSG_PEEK);
				/* DEBUG printf("%02X\n", c); */
				if ((n > 0) && (c == '\n'))
					recv(sock, &c, 1, 0);
				else
					c = '\n';
			}
			buf[i] = c;
			i++;
		} else
			c = '\n';
	}
	buf[i] = '\0';
	return (i);
}

//404 error
void Server::not_found(int client) {
	char buf[1024];

	sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-Type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "your request because the resource specified\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "is unavailable or nonexistent.\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "</BODY></HTML>\r\n");
	send(client, buf, strlen(buf), 0);
}

//返回请求的静态资源
void Server::serve_file(int client, const char *filename) {
	FILE *resource = NULL;
	int numchars = 1;
	char buf[1024];

	buf[0] = 'A';
	buf[1] = '\0';
	while ((numchars > 0) && strcmp("\n", buf)) /* read & discard headers */
		numchars = get_line(client, buf, sizeof(buf));

	resource = fopen(filename, "r");
	if (resource == NULL)
		not_found(client);
	else {
		headers(client, filename);
		page_cat(client, resource);
	}
	fclose(resource);
}

//响应头
void Server::headers(int client, const char *filename) {
	char buf[1024];
	(void) filename; /* could use filename to determine file type */

	strcpy(buf, "HTTP/1.0 200 OK\r\n");
	int ret = send(client, buf, strlen(buf), 0);
	assert(ret >= 0);
	strcpy(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-Type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	strcpy(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
}

//读取文件
void Server::cat(int client, FILE *resource) {
	char buf[1024];

	fgets(buf, sizeof(buf), resource);
	while (!feof(resource)) {
		send(client, buf, strlen(buf), 0);
		fgets(buf, sizeof(buf), resource);
	}
}

//文件读取函数版本2, 一个字符一个字符的读取。
void Server::page_cat(int client,FILE* resource)
{
	int c;
	while((c = fgetc(resource))!=EOF)
	{
		send(client,&c,1,0);
	}
}
//执行cgi
void Server::exec_get_cgi(int client, const char *path, const char *method,
		const char *query_string)
{
	printf(" path:%s\n method:%s\n query_string:%s\n",path,method,query_string);
	char query_env[1024];
	    char type[16]="text/html";
	    pid_t pid;
	    int status;
	    int cgi_output[2];
	    int cgi_input[2];

	    if(pipe(cgi_output)<0)
	    {
	        cannot_execute(client);
	        return;
	    }
	    if(pipe(cgi_input)<0)
	    {
	    	cannot_execute(client);
	        return;
	    }

	    if((pid=fork())<0)
	    {
	    	cannot_execute(client);
	        return;
	    }
	    if(pid==0)//child
	    {
	        dup2(cgi_output[1],1);//cgi的输出端绑定文件描述符为1的输出端
	        dup2(cgi_input[0],0);
	        close(cgi_output[0]);
	        close(cgi_input[1]);
	        sprintf(query_env,"QUERY_STRING=%s",query_string);
	        putenv(query_env);
	        execl(path,path,query_string,(char*)0);
	        exit(0);
	    }
	    else //parent
	    {
	        char c;
	        close(cgi_output[1]);//取消绑定
	        close(cgi_input[0]);
	      //  headers(client,"index.html");
	      //  while(read(cgi_output[0],&c,1)>0)
	       //     send(client,&c,1,0);
	        read(cgi_output[0],&c,1);
	        if(c=='1') serve_file(client,"htdocs/log_suc.html");
	        else serve_file(client,"htdocs/log_fault.html");

	        close(cgi_output[0]);
	        close(cgi_input[1]);
	        waitpid(pid,&status,0);
	    }
	    return;
}

//cgi脚本不能执行
void Server::cannot_execute(int client) {
	char buf[1024];

	sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
	send(client, buf, strlen(buf), 0);
}
