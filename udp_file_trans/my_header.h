/*
 * my_header.h
 *
 *  Created on: 2015-3-29
 *      Author: panzg
 */

#ifndef MY_HEADER_H_
#define MY_HEADER_H_

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<assert.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/sendfile.h>
#include<string>
#include<vector>
#include<iostream>
#include <sys/stat.h>

using namespace std;

//定义文件传输包头
typedef struct file_header{
	char file_name[20];     /*文件名*/
	unsigned long file_size; /*文件大小*/
	unsigned long  suc_send_size; /*已发送文件大小*/
}file_header;

unsigned long get_file_size(const char *path)
{
   unsigned long filesize = -1;
   struct stat statbuff;
   if(stat(path, &statbuff) < 0)
   {
       return filesize;
   }
   else
   {
       filesize = statbuff.st_size;
   }
   return filesize;
}


#endif /* MY_HEADER_H_ */
