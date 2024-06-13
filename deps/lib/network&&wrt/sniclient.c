/*
 * SniClient.c
 *
 *  Created on: Jan 29, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>
#include <unistd.h>  	/*Header file for sleep(). man 3 sleep for details.*/
#include <pthread.h>	/* http://www.csc.villanova.edu/~mdamian/threads/posixthreads.html */
#include "sniproxy.h"
#include "log/log.h"
#include <string.h>
#include "sniclient.h"
#include <socks.h>
#include "net.h"
#include <stdint.h>


void *SniClientHandler(void *arg)
{
	if (!arg) pthread_exit(0);
	sniclient_t *client = (sniclient_t*)arg;
	sockshost_t *socks = client->SniConfig.Socks;
	lport_t 	xport = client->SniConfig.Port;

	//log_info("client thread %i",client->connid);
	uint8_t buffer[0x2000]; /*8Kb memory tmp*/
	uint32_t Windex = 0;
	char HostName[_MaxHostName_] = {0};
	uint32_t TotalRx = 0;
	uint32_t TotalTx = 0;
	fd_set rfds;
	struct timeval tv;
	while(1)
	{

		FD_ZERO(&rfds);
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		FD_SET(client->connid,&rfds);
		if (select(FD_SETSIZE, &rfds, NULL, NULL, &tv) < 0)	/*wait for socket data ready*/
		{
			log_error("Err in select");
			break;
		}

		if(!FD_ISSET( client->connid, &rfds ))
		{

			log_info("TimeOut tid:%i",client->connid);
			break;
		}

		int newData = read(client->connid, &buffer[Windex], sizeof(buffer) - Windex);/* read length of message */
		if (newData <= 0)
		{
			log_info("client %i disconnect %i",client->connid,newData);
			break;
		}

		Windex += newData;
		if(Windex>=sizeof(buffer))
		{
			log_error("Host Buffer OverFlow");
			break;
		}

		if(net_GetHost(buffer,Windex,HostName,_MaxHostName_))
		{
			/*Check host validate*/
			if(client->SniConfig.wlist && filter_IsWhite(client->SniConfig.wlist,HostName)==false)
			{
				log_info("SNI filter Host { %s }",HostName);
				break;
			}

			if(isTrueIpAddress(HostName))
			{
				log_info("SNI we can't support IP address");
				break;
			}

			log_info("SNI start Host { %s } ",HostName);
			int sockssocket = 0;
			if(socks)	/*Set Connect to socks*/
			{
				if(!socks5_connect(&sockssocket,socks,HostName,xport.remote_port,false))
					break;
			}
			else	/*connect directly*/
			{
				if(!net_connect(&sockssocket,HostName,xport.remote_port))
					break;
			}


			FD_ZERO(&rfds);

			int n;
			if(write(sockssocket,buffer,Windex)<Windex)
			{
				/*try close upstream socket*/
				close(sockssocket);
				break;
			}
			TotalTx += Windex;

			while(1)
			{
				tv.tv_sec  = 300;
				tv.tv_usec = 0;
				FD_SET(sockssocket,&rfds);
				FD_SET(client->connid,&rfds);
				if (select(FD_SETSIZE, &rfds, NULL, NULL, &tv) < 0)
				{
					log_error("SNI error in select");
					break;
				}

				if( FD_ISSET( sockssocket, &rfds ) )
				{
					/* data coming in */
					if((n=read(sockssocket,buffer,sizeof(buffer)))<1) break;
					if(write(client->connid,buffer,n)<n) break;
					TotalRx += n;
				}
				else if(FD_ISSET( client->connid, &rfds ) )
				{
					/* data going out */
					if((n=read(client->connid,buffer,sizeof(buffer)))<1) break;
					if(write(sockssocket,buffer,n)<n) break;
					TotalTx += n;
				}
				else
				{
					/*timeout wait for read socket*/
					log_info("SNI timeout Host { %s }",HostName);
					break;
				}
			}
			
			/*try close upstream socket*/
			close(sockssocket);
			break;
		}
	}

	log_info("SNI end Host{ %s } txrx(%i/%i)",HostName,TotalRx,TotalTx);

	if(client->SniConfig.sta)	/*Update statistics*/
	{
		state_RxTxClose(client->SniConfig.sta,TotalRx,TotalTx);
	}

	/* close socket and clean up */
	close(client->connid);
	free(client);
	pthread_exit(0);
}
