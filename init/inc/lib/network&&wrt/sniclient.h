/*
 * SniClient.h
 *
 *  Created on: Jan 29, 2020
 *      Author: zeus
 */

#ifndef SNICLIENT_H_
#define SNICLIENT_H_
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

typedef struct
{
	int		 connid;
	struct sockaddr_in cli;
	socklen_t addr_len;
	SniServer_t SniConfig;
}sniclient_t;


void *SniClientHandler(void *arg);


#endif /* SNICLIENT_H_ */
