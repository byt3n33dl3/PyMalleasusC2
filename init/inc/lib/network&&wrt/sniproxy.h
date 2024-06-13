/*
 * SniProxy.h
 *
 *  Created on: Jan 28, 2020
 *      Author: zeus
 */

#ifndef SNIPROXY_H_
#define SNIPROXY_H_
#include <stdint.h>
#include <stdbool.h>
#include <statistics.h>
#include <filter/filter.h>
#include <socks.h>
#include <xpoll.h>

#define MAX_SNI_PACKET	4096
#define SNI_BUFFER_SIZE	8192
typedef struct
{
	char	 bindip[_MaxIPAddress_];
	uint16_t local_port;
	uint16_t remote_port;
	void 	 *next;
}lport_t;

typedef struct
{
	lport_t 	Port;
	sockshost_t	 *Socks;
	statistics_t *sta;
	filter_t	 *wlist;
	bool UserInternalDNS;
	char DNSServer[20];
}SniServer_t;

typedef struct 
{
	int				fd;
	uint32_t		total_rx;
	xevent_t		*ev;
}sni_ctx_t;


typedef struct
{
	char 	 hostname[_MaxHostName_];
	uint8_t  sni_packet[MAX_SNI_PACKET];
	uint32_t w_index;
	bool	 is_sni_mark;
	int		 sockfd;
}sni_link_t;

typedef struct
{
	sni_ctx_t		user;
	sni_ctx_t		server;
	sni_link_t		sni_data;
	SniServer_t 	sni_config;
}server_t;


bool SniProxy_Start(xpoll_t *eloop,SniServer_t *Sni);

#endif /* SNIPROXY_H_ */
