/*
 * sip_sock.c
 *
 *  Created on: 2015-6-11
 *      Author: panzg
 */


#include"sip.h"
static struct sock *sock_list[128];
struct sock *sip_get_sock(int fd)
{
	return sock_list[fd];
}

struct sock* SIP_SockNew(int t)
{
	struct sock* sock;
	int size;

	sock =(struct sock *) malloc(sizeof(struct sock));
	if (sock == NULL)
	{
		return NULL;
	}

	sock->err = 0;
	sock->type = t;
	sock->pcb.tcp = NULL;

	if (sem_init(&sock->sem_recv,0, 0))
	{
		free(sock);
		return NULL;
	}

	sock->state        = NETCONN_NONE;
	/* initialize socket to -1 since 0 is a valid socket */
	sock->socket       = -1;
	sock->recv_avail   = 0;
	sock->recv_timeout = 0;

	return sock;
}

int SIP_SockDelete(struct sock *sock)
{
	if(sock ==NULL) return -1;
	sock->pcb.tcp = NULL;
	free(sock);

	return 0;
}

int SIP_SockBind(struct sock *sock,struct in_addr *addr,__u16 port)
{
	if(sock->pcb.tcp!=NULL)
	{
		switch (sock->type) {
			case SOCK_RAW:

				break;
			case SOCK_DGRAM:
				sock->err = SIP_UDPBind(sock->pcb.udp,addr,port);
				break;
			case SOCK_STREAM:
				break;
			default:
				break;
		}
	}
	else
		sock->err = -1;
}

int SIP_SockConnect(struct sock *sock, struct in_addr *addr, __u16 port)
{
  	if (sock->pcb.tcp == NULL)
	{
		return -1;
	}

  	switch (sock->type)
	{
		case SOCK_RAW:
			//conn->err = raw_connect(conn->pcb.raw,addr);
			break;
		case SOCK_DGRAM:
			sock->err = SIP_UDPConnect(sock->pcb.udp, addr, port);
			break;
		case SOCK_STREAM:
			break;
		default:
			break;
	}
}
int SIP_SockDisconnect(struct sock *sock)
{
	 if (sock->type == SOCK_DGRAM)
	 {
	 	SIP_UDPDisconnect(sock->pcb.udp);
	}
}


/**
 * Receive data (in form of a skbuff containing a packet buffer) from a sock
 *
 * @param conn the sock from which to receive data
 * @return a new skbuff containing received data or NULL on memory error or timeout
 */
struct skbuff * SIP_SockRecv(struct sock *sock)
{
	struct skbuff *skb_recv = NULL;

		int num =0;
		if(sem_getvalue(&sock->sem_recv, &num))		/*获得信号量的值*/
		{											/*没有接收到网络数据*/
			struct timespec timeout ;
	#if 0
		struct timespec {
	             time_t tv_sec;      /* Seconds */
	             long   tv_nsec;     /* Nanoseconds [0 .. 999999999] */
	         };
	#endif
			timeout.tv_sec = sock->recv_timeout;		/*超时时间为sock结构中设置*/
			timeout.tv_nsec = 0;
			sem_timedwait(&sock->sem_recv, &timeout);	/*超时等待网络数据的到来*/
		}
		else
		{
			sem_wait(&sock->sem_recv);				/*已经有数据,直接获取数据*/
		}

		skb_recv = sock->skb_recv;					/*获得接收缓冲区的指针头部*/
		if(skb_recv == NULL)
			return NULL;

		sock->skb_recv = skb_recv->next;				/*将头部的网络数据单元从接收缓冲区上摘除*/
		skb_recv->next = NULL;

		return skb_recv;								/*返回一个网络结构*/
}

/**
 * Send data (in form of a skbuff) to a specific remote IP address and port.
 * Only to be used for UDP and RAW netconns (not TCP).
 *
 * @param conn the sock over which to send data
 * @param buf a skbuff containing the data to send
 * @param addr the remote IP address to which to send the data
 * @param port the remote port to which to send the data
 * @return ERR_OK if data was sent, any other err_t on error
 */
int SIP_SockSendTo(struct sock *conn, struct skbuff *skb, struct in_addr *addr, __u16 port)
{
if (conn->pcb.tcp != NULL)
	{
		switch (conn->type)
		{
			case SOCK_RAW:
				//conn->err = raw_sendto(conn->pcb.raw, skb, addr);
				break;
			case SOCK_DGRAM:
				conn->err = SIP_UDPSendTo(conn->pcb.udp, skb, addr, port);
				break;
			default:
				break;
		}
	}

	return -1;
}


/**
 * Send data over a UDP or RAW sock (that is already connected).
 *
 * @param conn the UDP or RAW sock over which to send data
 * @param buf a skbuff containing the data to send
 * @return ERR_OK if data was sent, any other err_t on error
 */
int SIP_SockSend(struct sock *sock, struct skbuff *skb)
{
	if (sock->pcb.tcp != NULL)
	{
		switch (sock->type)
		{
			case SOCK_RAW:
				//conn->err = raw_send(conn->pcb.raw, skb);
				break;
			case SOCK_DGRAM:
				sock->err = SIP_UDPSend(sock->pcb.udp, skb);
				break;
			default:
				break;
		}
	}
}
