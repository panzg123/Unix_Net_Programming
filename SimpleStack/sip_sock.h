/*
 * sip_sock.h
 *
 *  Created on: 2015-6-11
 *      Author: panzg
 */
#ifndef __SIP_SOCK_H__
#define __SIP_SOCK_H__



struct sock;

#if 0
struct sock_common {
	unsigned short		skc_family;
	volatile __u8	skc_state;
	unsigned int		skc_hash;
};

struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_hash			__sk_common.skc_hash
	__u8		sk_protocol;
	unsigned short		sk_type;
	union{
		struct udp_pcb *upcb;
	}pcb;
	int			sk_rcvbuf;
	struct sip_sk_buff_head	sk_receive_queue;
	struct sip_sk_buff_head	sk_write_queue;
	struct sip_sk_buff_head	sk_async_wait_queue;
	unsigned short		sk_ack_backlog;
	unsigned short		sk_max_ack_backlog;
	__u32			sk_priority;
	long			sk_rcvtimeo;
	long			sk_sndtimeo;
	void			*sk_protinfo;
	void			*sk_user_data;
	__u32			sk_sndmsg_off;
	int			sk_write_pending;
	void			*sk_security;
};
#endif

#endif/*__SIP_SOCK_H__*/
