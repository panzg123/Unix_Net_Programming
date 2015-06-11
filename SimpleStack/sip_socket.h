/*
 * sip_socket.h
 *
 *  Created on: 2015-6-11
 *      Author: panzg
 */

#ifndef SIP_SOCKET_H_
#define SIP_SOCKET_H_


struct sip_socket
{
	/*协议无关层的结构指针，一个socket对应一个sock*/
	struct sock *sock;
	/*最后接受的网络数据*/
	struct skbuff *lastdata;
	/*接受的网络数据的偏移量，由于不能一次将网络数据拷贝给用户*/
	__u16 lastoffset;

	/*错误值*/
	int err;
};



#endif /* SIP_SOCKET_H_ */
