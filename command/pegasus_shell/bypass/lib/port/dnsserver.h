/*
 * DnsServer.h
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */

#ifndef DNSSERVER_H_
#define DNSSERVER_H_
#include <stdint.h>
#include <stdbool.h>
#include <config.h>
#include <socks.h>
#include <monitor.h>
#include <sys/socket.h>
#include <filter/filter.h>


typedef struct
{
	char 	 ip[_MaxIPAddress_];
	uint16_t port;
}dnsStream_t;

typedef struct
{
	filter_t 	  *whitelist;
	uint8_t		  sni_ip[4];
	dnsStream_t	  Local;
	dnsStream_t   Remote;
	sockshost_t	  *Socks;
	statistics_t  *Stat;
	uint32_t	  timeout;
}dnshost_t;

void dnsserver_init(dnshost_t *config);

#endif /* DNSSERVER_H_ */
