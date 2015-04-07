// Winsock_IOmodel_Client.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <WinSock2.h>  
#include <stdio.h>  
#define SERVER_ADDRESS "127.0.0.1"  
#define PORT       8000  
#define MSGSIZE    1024  
#pragma comment(lib, "ws2_32.lib")  
int main()  
{  
	//用作WSAStartup()函数的第二个参数，接收Windows Sockets实现的细节。  
	WSADATA wsaData;  
	//用来与服务器socket进行通信的客户端socket。  
	SOCKET sClient;  
	//用来设置服务器的地址信息。  
	SOCKADDR_IN server;  
	char szMessage[MSGSIZE];  
	int ret;   
	//第一步：初始化Winsock库  
	WSAStartup(0x0202, &wsaData);  
	//第二步：创建用来与服务器进行通信的客户端  
	sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  
	//第三步：将服务器端的地址信息保存入SOCKADDR_IN类型的变量sever中  
	memset(&server, 0, sizeof(SOCKADDR_IN));  
	server.sin_family = AF_INET;  
	server.sin_addr.S_un.S_addr = inet_addr(SERVER_ADDRESS);  
	server.sin_port = htons(PORT);  
	//第四步：通过connect函数向服务器发起连接。  
	connect(sClient, (struct sockaddr *)&server, sizeof(SOCKADDR_IN));  
	while (TRUE)  
	{  
		//连接服务器成功后，客户端控制台窗口将显示Send:  
		printf("Send:");  
		//将用户输入的内容保存到szMessage中  
		gets(szMessage);  
		//发送消息将szMessage中的内容通过sClient发往服务器  
		send(sClient, szMessage, strlen(szMessage), 0);  
		//将接收到的内容放入szMessage中  
		ret = recv(sClient, szMessage, MSGSIZE, 0);  
		szMessage[ret] = '\0';  
		printf("Received [%d bytes]: '%s'\n", ret, szMessage);  
	}  
	closesocket(sClient);  
	WSACleanup();  
	return 0;  
}  