/*
 * socks.h
 *
 *  Created on: Feb 1, 2020
 *      Author: zeus
 */

#ifndef SOCKS_H_
#define SOCKS_H_

#include <stdint.h>
#include <stdbool.h>
#include <config.h>

typedef struct
{
	char 	*host;
	uint16_t port;
	char	*user;
	char	*pass;
}sockshost_t;

typedef struct
{
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
}SocksReplayHeader_t;

typedef struct
{
	uint8_t ver;
	uint8_t status;
}SocksAuthenticationReplay_t;

bool socks5_connect(int *sockfd,sockshost_t *socks, const char *host, int port,bool keepalive);

#endif /* SOCKS_H_ */
