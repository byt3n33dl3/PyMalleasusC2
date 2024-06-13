/*
 * dnsproxy.h
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */

#ifndef DNSPROXY_H_
#define DNSPROXY_H_
#include <stdint.h>
#include <stdbool.h>
#include <config.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include "dnsserver.h"
#include <fifo.h>
#include <filter/filter.h>

#define DNS_MSG_SIZE	512
typedef struct
{
	uint16_t len;
	char message[DNS_MSG_SIZE];
	struct sockaddr_in client;
}dnsMessage_t;


#define D_FIFO_Message_Size	sizeof(dnsMessage_t)
#define D_FIFO_Item			128

typedef struct
{
	/* Fifo */
	fifo_t		  *fifo;
	
	/* whitelist*/
	filter_t *whitelist;
	
	/*sni server ip*/
	uint8_t sni_ip[4];

	/*bind ip/port*/
	char 	 	  listen_addr[_MaxIPAddress_];
	char	 	  listen_port[_MaxPORTAddress_];

	dnsStream_t   upstream;
	sockshost_t	  *socks;
	uint32_t	  timeout;
	
	/*socket file handler*/
	int local_sock;
	statistics_t  *Stat;
}dnsserver_t;


dnsserver_t *localdns_init_config(dnshost_t *conf);
void localdns_free(dnsserver_t *dns);

bool localdns_init_sockets(dnsserver_t *dns);
bool localdns_pull(dnsserver_t *dns);

#endif /* DNSPROXY_H_ */
