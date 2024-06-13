/*
 * pargs.h
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */

#ifndef ARGS_H_
#define ARGS_H_
#include <stdint.h>
#include <stdbool.h>
#include <sniproxy.h>
#include <dnsserver.h>

#define DEF_CONFIG_PATH	"zroxy.conf"

typedef struct
{
	lport_t 	*ports;
	sockshost_t *socks;
	uint16_t	*monitorPort;
	char 		*WhitePath;
	dnshost_t	*dnsserver;
}zroxy_t;

bool arg_Init(zroxy_t *pgp,int argc, const char **argv);
void print_usage(void);
void Free_PortList(zroxy_t *ptr);


#endif /* ARGS_H_ */
