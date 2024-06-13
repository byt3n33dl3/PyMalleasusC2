/*
 * socks.c
 *
 *  Created on: Feb 1, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>
#include <unistd.h>  	/*Header file for sleep(). man 3 sleep for details.*/
#include <pthread.h>	/* http://www.csc.villanova.edu/~mdamian/threads/posixthreads.html */
#include "log/log.h"
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "socks.h"
#include "net.h"


bool socks5_connect(int *sockfd,sockshost_t *socks, const char *host, int port,bool keepalive)
{
	uint16_t socks5_port = socks->port;
	char *socks5_host = socks->host;
	
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(socks5_port);
	//serv_addr.sin_addr.s_addr = inet_addr(socks5_host);

	/*if host is domain need resolve domain*/
	bool status = net_connect(sockfd,socks5_host, socks5_port);
	if (!status)
	{
		log_error("Socks Error: Connect to %s Failed", socks5_host);
		return false;
	}

	if(keepalive)
    {
        net_enable_keepalive(*sockfd);
    }

	uint8_t Tempbuf[300] = {0};
    // SOCKS5 CLIENT HELLO
    // +-----+----------+----------+
    // | VER | NMETHODS | METHODS  |
    // +-----+----------+----------+
    // |  1  |    1     | 1 to 255 |
    // +-----+----------+----------+
	write(*sockfd,"\x05\x02\x00\x02",4);	/*Write Hello*/

    // SOCKS5 SERVER HELLO
    // +-----+--------+
    // | VER | METHOD |
    // +-----+--------+
    // |  1  |   1    |
    // +-----+--------+
	 uint8_t SocksVer = 0;
	 if(read(*sockfd,&SocksVer,sizeof(uint8_t))<=0)
	 {
		 log_error("[!] Error Read Socks Ver");
		 close(*sockfd);
		 return false;
	 }

	 if(SocksVer!=5)
	 {
		 log_error("[!] We can not support ver %d",SocksVer);
		 close(*sockfd);
		 return false;
	 }

	 uint8_t SocksMethod;
	 if(read(*sockfd,&SocksMethod,sizeof(uint8_t))<=0)
	 {
		 log_error("[!] Error Read Socks Method");
		 close(*sockfd);
	 	 return false;
	 }

	 if(!(SocksMethod==0 || SocksMethod==2))
	 {
		 log_error("[!] We can not support Method %d",SocksMethod);
		 close(*sockfd);
		 return false;
	 }
	

	if(SocksMethod==2)
	{
		/*Authentication With Socks,
		*
		* From RFC1929:
		* Once the SOCKS V5 server has started, and the client has selected the
		* Username/Password Authentication protocol, the Username/Password
		* subnegotiation begins.  This begins with the client producing a
		* Username/Password request:
		*
		* +----+------+----------+------+----------+
		* |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		* +----+------+----------+------+----------+
		* | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		* +----+------+----------+------+----------+
		*
		* The VER field contains the current version of the subnegotiation,
		* which is X'01'
		*/
		uint8_t uLen = strlen(socks->user);
		uint8_t pLen = strlen(socks->pass);
		char temp[512+4] = {0};
		int packet_len = sprintf(temp,"\x01%c%s%c%s",uLen,socks->user,pLen,socks->pass);
		
		write(*sockfd,temp,packet_len); /*write UserPass*/

		SocksAuthenticationReplay_t SocksAuth;
	 	if(read(*sockfd,&SocksAuth,sizeof(SocksAuthenticationReplay_t))<=0)
	 	{
			log_error("[!] Error Read Socks Authentication");
			close(*sockfd);
	 		return false;
		}

		if(SocksAuth.status!=0)
		{
			log_error("[!] Error Socks Authentication:%02X",SocksAuth.status);
			close(*sockfd);
	 		return false;
		}
	}

	 /*check domain or ip*/
	 in_addr_t host_ip = inet_addr(host);

	 // SOCKS5 CLIENT REQUEST
	 // +-----+-----+-------+------+----------+----------+
	 // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	 // +-----+-----+-------+------+----------+----------+
	 // |  1  |  1  | X'00' |  1   | Variable |    2     |
	 // +-----+-----+-------+------+----------+----------+
	 Tempbuf[0] = 0x05;  // VER 5
	 Tempbuf[1] = 0x01;  // CONNECT
	 Tempbuf[2] = 0x00;

	 uint16_t datalen = 10;
	 /*if it's Domain*/
	 if(host_ip==-1)
	 {
		 /*if host is domain*/
		 Tempbuf[3] = 0x03;  // Domain name
		 Tempbuf[4] = (uint8_t)strlen(host);
		 memcpy(Tempbuf + 5, host, Tempbuf[4]);				    /*copy host*/
		 *(uint16_t *)(Tempbuf + 5 + Tempbuf[4]) = htons(port); /*copy port*/
		 datalen = 5 + Tempbuf[4] + 2;
	 }
	 else
	 {
		 /*if host is ip*/
		 Tempbuf[3] = 0x01;	/*IP V4 address*/
		 memcpy(Tempbuf + 4, &host_ip, 4);		   /*copy ip*/
		 *(uint16_t *)(Tempbuf + 8) = htons(port); /*copy port*/
	 }

	 write(*sockfd,Tempbuf,datalen);

    // SOCKS5 SERVER REPLY
    // +-----+-----+-------+------+----------+----------+
    // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +-----+-----+-------+------+----------+----------+
    // |  1  |  1  | X'00' |  1   | Variable |    2     |
    // +-----+-----+-------+------+----------+----------+
	 SocksReplayHeader_t Replay;
	 if(read(*sockfd,&Replay,sizeof(SocksReplayHeader_t))<=0)
	 {
		 log_error("[!] Error Read Replay");
		 close(*sockfd);
	 	 return false;
	 }

	 if(Replay.ver!=5)
	 {
		log_error("[!] Error Socks Ver");
		close(*sockfd);
		return false;
	 }

	 if(Replay.rep!=0)
	 {
		log_error("[!] Error Success Command: %d",Replay.rep);
		close(*sockfd);
		return false;
	 }

	 if(Replay.atyp == 0x01)	// IPv4 address
	 {
		 if(read(*sockfd,Tempbuf,4)<=0)
		 {
		 	 log_error("[!] Error Read Replay");
		 	 close(*sockfd);
		 	 return false;
		 }
	 }
	 else if (Replay.atyp == 0x03)	// Domain name
	 {
		 uint8_t len;
		 if(read(*sockfd,&len,sizeof(uint8_t))<=0)
		 {
		  	 log_error("[!] Error Read Replay");
		  	 close(*sockfd);
		  	 return false;
		 }

		 if(read(*sockfd,&Tempbuf,len)<=0)
		 {
		  	 log_error("[!] Error Read Replay");
		  	 close(*sockfd);
		  	 return false;
		 }
	 }
	 else if (Replay.atyp == 0x04)	// IPv6 address
	 {
		 if(read(*sockfd,&Tempbuf,16)<=0)
		 {
		   	 log_error("[!] Error Read Replay");
		   	 close(*sockfd);
		   	 return false;
		 }
	 }
	 else
	 {
		 log_error("[!] unsupported address type");
		 close(*sockfd);
		 return false;
	 }

	 if(read(*sockfd,&Tempbuf,sizeof(uint16_t))<=0)	/*Read Port*/
	 {
	   	 log_error("[!] Error Read Replay");
	   	  close(*sockfd);
	   	 return false;
	 }

	 return true;
}
