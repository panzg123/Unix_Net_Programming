/*
 * client.cpp
 *
 *  Created on: 2015-3-29
 *      Author: panzg
 */

/*
* 使用poll同时监听用户输入和网络连接，并用splice函数实现重定向，提高效率。
* 客户端的两个功能：
    1.从标准输入终端读取数据，将数据发送到服务器;
    2.在标准输出终端上打印服务器发送给他的数据;
*/
#include"my_header.h"
#include<poll.h>
#define _GNU_SOURCE 1
#define BUFFER_SIZE 1024*8
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8001



//字符串分割函数
vector<std::string> split(std::string str,std::string pattern)
 {
     std::string::size_type pos;
     std::vector<std::string> result;
     str+=pattern;//扩展字符串以方便操作
     int size=str.size();

     for(int i=0; i<size; i++)
     {
         pos=str.find(pattern,i);
         if(pos<size)
         {
             std::string s=str.substr(i,pos-i);
             result.push_back(s);
             i=pos+pattern.size()-1;
         }
     }
     return result;
}
int main(int argc,char** argv)
{
    /*
    if(argc<=2)
    {
        printf("wrong args numbers\n");
        return 1;
    }
    */
    const char* ip = SERVER_IP;
    int port = SERVER_PORT;

    //ip list server
    struct sockaddr_in server_addr;
    bzero(&server_addr,sizeof(server_addr));
    inet_pton(AF_INET,ip,&server_addr.sin_addr);
    server_addr.sin_port = port;
    server_addr.sin_family = AF_INET;

    //other client
    struct sockaddr_in other_client_addr;
    bzero(&other_client_addr,sizeof(other_client_addr));
    inet_pton(AF_INET,ip,&other_client_addr.sin_addr);
    other_client_addr.sin_port = port;
    other_client_addr.sin_family = AF_INET;

    //clinet bind
    int sockfd = socket(AF_INET,SOCK_DGRAM,0);
    assert(sockfd != -1);
    char clientip[20];
    int clientport;
    printf("pls enter your ip and port:\n");
    scanf("%s %d",clientip,&clientport);
    struct sockaddr_in client_addr;
    bzero(&client_addr,sizeof(client_addr));
    inet_pton(AF_INET,clientip,&client_addr.sin_addr);
    client_addr.sin_port = clientport;
    client_addr.sin_family = AF_INET;
    bind(sockfd,(sockaddr*)&client_addr,sizeof(client_addr));

    /*
    if(connect(sockfd,(struct sockaddr*)&server_addr,sizeof(server_addr)) <0 )
	{
		printf("connect failed!\n");
		close(sockfd);
		return 1;
	}
    */

    char Buffer[BUFFER_SIZE];
    memset(Buffer,'\0',BUFFER_SIZE);
    sprintf(Buffer,"onln %s %d",clientip,clientport);
    int sendlen = sendto(sockfd,Buffer,sizeof(Buffer),0,(sockaddr*)&server_addr,sizeof(server_addr));
    assert(sendlen >= 0);
   // printf("send %s msg success!\n",Buffer);
   // printf("pls enter the command!\n");
    //注册文件描述符0（标准输入）和文件描述符socklistenfd上的可读事件
    pollfd fds[2];
    fds[0].events = POLLIN;
    fds[0].fd = 0;
    fds[0].revents = 0;
    fds[1].fd =sockfd;
    fds[1].events = POLLRDHUP|POLLIN;
    fds[1].revents = 0;

    char read_buffer[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE];
    sockaddr_in recv_sockfd;
    socklen_t recv_sockfd_len = sizeof(sockaddr_in);

    while(1)
    {
        int ret = poll(fds,2,-1);
        if(ret < 0)
        {
            printf("poll failed!\n");
            break;
        }
        if(fds[1].revents & POLLRDHUP)
        {
            printf("server close the connection\n");
            break;
        }
        //接受来自其他的可读消息
        if(fds[1].revents & POLLIN)
        {
            memset(read_buffer,'\0',BUFFER_SIZE);
            //打开文件，准备写入
            		//循环recv并写入文件
            		int lenght = recvfrom(fds[1].fd,read_buffer,BUFFER_SIZE,0,(sockaddr*)&recv_sockfd,&recv_sockfd_len);
            		if(read_buffer[0] == '1')
            		{
            			//char file_name[]="test_recv_client.txt";
            			char file_name[20];
            			file_header my_file_header;
            			memcpy(&my_file_header,read_buffer+1,40);
            			strncpy(file_name,my_file_header.file_name,20);
            			if((my_file_header.suc_send_size+lenght-41) == my_file_header.file_size)
            			{
            				printf("接受来自:%s;文件:%s;大小：%lu字节;已成功接收\n",
            					inet_ntoa(recv_sockfd.sin_addr),my_file_header.file_name,my_file_header.file_size);
            			}
            			FILE *fp = fopen(file_name,"a+b");
            			assert(fp != NULL);
            			 if (fwrite(read_buffer+41,sizeof(char),lenght-41,fp) < lenght-41)
            			 {
            			          printf("File write failed!\n");
            			}
            			 fclose(fp);
            		}
            		else if(read_buffer[0] =='2') printf("online list: %s\n",read_buffer+1);
            		else printf("recv msgs from %s: %s\n",inet_ntoa(recv_sockfd.sin_addr),read_buffer+1);
            //  recvfrom(fds[1].fd,read_buffer,BUFFER_SIZE-1,0,(sockaddr*)&recv_sockfd,&recv_sockfd_len);
         //   recv(fds[1].fd,read_buffer,BUFFER_SIZE-1,0);
        }
        //从0表述符到网络的重定向
        if(fds[0].revents & POLLIN)
        {
         //   ret = splice(0,NULL,pipefd[1],NULL,32768,SPLICE_F_MORE | SPLICE_F_MOVE);
          //  ret = splice(pipefd[0],NULL,sockfd,NULL,32768,SPLICE_F_MORE | SPLICE_F_MOVE);
          memset(send_buffer,'\0',BUFFER_SIZE);
         //  scanf("%[^\n]",send_buffer);
          cin.getline(send_buffer,100);
		//定义四个命令：file,list,msgs
        //有bug，第一个读入空命令
     //     printf("command: %s\n",send_buffer);
          if(strlen(send_buffer)>=4)
	      {
			 char command[5];
			 command[4]='\0';
			 strncpy(command,send_buffer,4);  //命令
			 string str_ip_port_msgs(send_buffer);   //第二部分
			 vector<std::string> result=split(str_ip_port_msgs," ");

			 //文件
			 if(strcmp(result.at(0).c_str(),"file")==0)
			 {
					printf("file command!\n");

					//发送文件
				//	char file_name[] = "test.txt";
					FILE *fp = fopen(result.at(3).c_str(), "rb");
					assert(fp !=NULL);
					char buffer[1024];
					memset(buffer, 0, BUFFER_SIZE);
					int read_lenght = 0, send_lenght = 0;
				    inet_pton(AF_INET,result.at(1).c_str(),&other_client_addr.sin_addr);
					other_client_addr.sin_port = atoi(result.at(2).c_str());
					//循环读取文件内容，并发送。

					//头部第一位表示文件，第2-41表示文件头
					file_header  myheader;
					unsigned long suc_send_size = 0;
					memset(myheader.file_name,'\0',20);
					strcpy(myheader.file_name,result.at(3).c_str());
					myheader.file_size = get_file_size(myheader.file_name);
					while ((read_lenght = fread(buffer+41, sizeof(char),BUFFER_SIZE-41, fp)) > 0)
					{
						buffer[0] = '1';
						myheader.suc_send_size = suc_send_size;
						memcpy(buffer+1,&myheader,sizeof(myheader));
						//strcpy(buffer+1,myheader.file_name);
						if ((send_lenght = sendto(fds[1].fd, buffer, read_lenght+41,0, (sockaddr*) &other_client_addr,sizeof(other_client_addr))) < 0)
						{
							printf("Send file Failed\n");
							return 1;
						}
						suc_send_size += read_lenght;
						usleep(5000);
						memset(buffer, 0, BUFFER_SIZE);
					}
					if(suc_send_size == myheader.file_size)
						printf("文件:%s 大小%lu字节，发送成功！\n",myheader.file_name,myheader.file_size);
					fclose(fp);
				//	sendto(fds[1].fd, send_buffer, sizeof(send_buffer), 0,(sockaddr*) &server_addr, sizeof(server_addr));
			 }
			 else if(strcmp(result.at(0).c_str(),"list")==0)
			 {
				printf("list command!\n");
				sendto(fds[1].fd,send_buffer,sizeof(send_buffer),0,(sockaddr*)&server_addr,sizeof(server_addr));
			 }
			 else if(strcmp(result.at(0).c_str(),"msgs")==0)
			 {
                //向其他客户端发送消息
				printf("msgs command!\n");
			    inet_pton(AF_INET,result.at(1).c_str(),&other_client_addr.sin_addr);
			    other_client_addr.sin_port = atoi(result.at(2).c_str());
			    string str_msgs="0";
			    for (int i = 3; i < result.size(); ++i) {
			    	str_msgs+=result.at(i);
			    	str_msgs+=" ";
				}
				sendto(fds[1].fd,str_msgs.c_str(),strlen(str_msgs.c_str()),0,(sockaddr*)&other_client_addr,sizeof(other_client_addr));
				cout<<"消息:"<<str_msgs<<",发送成功！\n";
			 }
			 else printf("未知命令\n");

          }

		   //如果是q，则退出
            else if(strcmp(send_buffer,"q")==0)
            {
                printf("客户端退出\n");
                sprintf(Buffer,"ofln %s %d",clientip,clientport);
                sendto(fds[1].fd,Buffer,sizeof(Buffer),0,(sockaddr*)&server_addr,sizeof(server_addr));
                break;
            }
            else {}     //暂时不做处理
          //  else printf("少于4个字段，未知命令(有bug)\n");
          }
    	}
    close(sockfd);

    return 0;

}
