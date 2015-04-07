/*
 * server.cpp
 *
 *  Created on: 2015-3-29
 *      Author: panzg
 */
/*
* 功能：接受来自客户端的消息，转达给其他客户端。
*/
#define _GNU_SOURCE 1

#include "my_header.h"
#include <poll.h>


#define USER_LIMIT 5
#define BUFFER_SIZE 1024
#define FD_LIMIT 65535
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8001

vector<string> ip_port_vec;

struct client_data
{
    sockaddr_in address;
    char * write_buf;
    char buffer[BUFFER_SIZE];
};
int setnonblocking(int fd)
{
    int old_option = fcntl(fd,F_GETFL);
    int new_option = old_option | O_NONBLOCK;
    fcntl(fd,F_SETFL,new_option);
    return old_option;
}

int main(int argc,char **argv)
{
    /*
    if(argc <=2)
    {
        printf("wrong args number\n");
        return 1;
    }
    */
    const char* ip = SERVER_IP;
    int port = SERVER_PORT;

    int ret=0;
    struct sockaddr_in server_addr;
    bzero(&server_addr,sizeof(server_addr));
    inet_pton(AF_INET,ip,&server_addr.sin_addr);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;

    int listensockfd = socket(AF_INET,SOCK_DGRAM,0);
    assert(listensockfd != -1 );
    ret = bind(listensockfd,(sockaddr*)&server_addr,sizeof(server_addr));
    if(ret == -1)  {printf("%d\n",errno);return 0;}

   // ret = listen(listensockfd,USER_LIMIT);
    //assert(ret != -1);


    pollfd fds[2];
    fds[0].events =POLLIN | POLLERR;
    fds[0].fd = listensockfd;
    fds[0].revents = 0 ;

     fds[1].events = POLLIN;
     fds[1].fd = 0;
     fds[1].revents = 0;

    char recv_buffer[BUFFER_SIZE];
    sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while(1)
    {
         memset(recv_buffer,'\0',BUFFER_SIZE);
        ret = poll(fds,2,-1);
        if(ret <0)
        {
            printf("poll failed!\n");
            break;
        }
        if(fds[0].revents & POLLIN)
        {
            /*
            recv(fds[0].fd,recv_buffer,BUFFER_SIZE,0);
            printf("%s\n",recv_buffer);
            */
             recvfrom(fds[0].fd,recv_buffer,BUFFER_SIZE,0,(sockaddr*)&client_addr,&client_len);
               printf("recv msg :%s\n",recv_buffer);
             char command[5];
             char client_ip_port[20];
             memset(client_ip_port,'\0',20);
			 for(int i=0;i<4;i++) command[i] = recv_buffer[i];
			 command[4] = '\0';
			 strncpy(client_ip_port,recv_buffer+5,sizeof(recv_buffer)-5);
            //strncpy会修改recv_buffer吗
	//		 strncpy(command,recv_buffer,4);

		//	 printf("%s\n",client_ip_port);
		//	 printf("%s\n",command);
			 if(strcmp(command,"onln")==0)
			 {
				printf("client online --->%s\n",client_ip_port);
				string strvectemp(client_ip_port);
                ip_port_vec.push_back(strvectemp);
                vector<string>::iterator it = ip_port_vec.begin();
                while(it!=ip_port_vec.end())
                {
                    sendto(fds[0].fd,("2"+(*it)).c_str(),strlen((*it).c_str())+1,0,(sockaddr*)&client_addr,client_len);
                    ++it;
                }
			 }
			 else if(strcmp(command,"ofln")==0)
			 {
				printf("client offline --->%s\n",client_ip_port);
                for ( vector<string>::iterator it = ip_port_vec.begin();it != ip_port_vec.end(); ++it )
                    if(strcmp((*it).c_str(),client_ip_port)==0) { ip_port_vec.erase(it);break;}
			 }
			 else if(strcmp(command,"list")==0)
			 {
				 printf("ip list request from--->%s\n",client_ip_port);
				 vector<string>::iterator it = ip_port_vec.begin();
				 while(it!=ip_port_vec.end())
				 {
				      sendto(fds[0].fd,("2"+(*it)).c_str(),strlen((*it).c_str())+1,0,(sockaddr*)&client_addr,client_len);
				          ++it;
				 }
			 }
			 else
			 {
                printf("接收到无用信息\n");
			 }
        }
        if(fds[1].revents & POLLIN)
        {
            char q;
            scanf("%c",&q);
            if(q == 'q') { cout<<"服务器退出"<<endl;break;}
            else {cout<<"未知命令";}
        }
    }
    close(listensockfd);
    return 0;
}




