/*
 * net.c
 *
 *  Created on: Feb 9, 2020
 *      Author: zeus
 */
#include <stdbool.h>
#include <stdint.h>
#include <log/log.h>
#include <netinet/in.h>
#include <sys/socket.h> /*Lib Socket*/
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

void *MemSearch(const void *haystack_start, size_t haystack_len,
        		const void *needle_start, size_t needle_len);

bool net_enable_keepalive(int sock) 
{
    int yes = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) != 0)
        return false;

    int idle = 1;
    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int)) != 0)
        return false;

    int interval = 1;
    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int)) != 0)
        return false;

    int maxpkt = 10;
    if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int)) != 0)
        return false;

    return true;
}

bool net_connect(int *sockfd,const char *hostname, uint16_t port)
{
    /*check Hostname is IP or Domain*/
    if(isTrueIpAddress(hostname))
	{
        if((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	    {
	        log_error("Socks Error : Could not create socket");
	        return false;
	    }

        struct sockaddr_in serv_addr;
	    serv_addr.sin_family = AF_INET;
	    serv_addr.sin_port = htons(port);

        if(inet_pton(AF_INET, hostname, &serv_addr.sin_addr)<=0)
		{
			log_error("inet_pton error occured");
			return false;
		}

		if(connect(*sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		{
			log_error("net_connect Error : Connect Failed");
			return false;
		}
        
        return true;
	}

    char port_str[8] = {0};
    struct addrinfo hints;
    struct addrinfo *addrs=NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    snprintf(port_str,7,"%i",port);

    const int status = getaddrinfo(hostname, port_str, &hints, &addrs);
    if (status != 0)
    {
    	log_error("%s:%s -> %s\n", hostname,port_str, gai_strerror(status));
        return false;
    }

    int sfd;
    bool result = false;
    for (struct addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next)
    {
        sfd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
        if (sfd == -1)
        {
        	log_error("Socks Error : Could not create socket");
        	//freeaddrinfo(addrs);
            //return false;
            continue;
        }

        if (connect(sfd, addr->ai_addr, addr->ai_addrlen) != -1)
        {
            result = true;
            break;
        }

        close(sfd);
    }

    freeaddrinfo(addrs);
    *sockfd = sfd;
    return result;
}

bool net_ListenIp4(in_addr_t addr, uint16_t Port,int *sockfd)
{

	struct  sockaddr_in servaddr;

	/*
	 * 	╔═══════════╦══════════════════════════╗
		║           ║       Socket Type        ║
		║ Address   ╟────────────┬─────────────╢
		║ Family    ║ SOCK_DGRAM │ SOCK_STREAM ║
		╠═══════════╬════════════╪═════════════╣
		║ IPX/SPX   ║ SPX        │ IPX         ║
		║ NetBIOS   ║ NetBIOS    │ n/a         ║
		║ IPv4      ║ UDP        │ TCP         ║
		║ AppleTalk ║ DDP        │ ADSP        ║
		║ IPv6      ║ UDP        │ TCP         ║
		║ IrDA      ║ IrLMP      │ IrTTP       ║
		║ Bluetooth ║ ?          │ RFCOMM      ║
		╚═══════════╩════════════╧═════════════╝
	 */
	// socket create and verification
	*sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*sockfd == -1)
	{
	  log_error("socket creation on port %d failed.",Port);
	  return false;
	}
	bzero((void*)&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = addr;//htonl(INADDR_ANY);
	servaddr.sin_port = htons(Port);

	int opt = 1;
	if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt))<0)
	{
		close(*sockfd);
		log_error("socket setopt failed");
		return false;
	}

	// Binding newly created socket to given IP and verification
	if ((bind(*sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) < 0)
	{
		close(*sockfd);
		log_error("socket bind failed");
		return false;
	}

	// Now server is ready to listen and verification
	if ((listen(*sockfd, 10)) != 0)
	{
	   log_error("Listen failed on port %d",Port);
	   return false;
	}

	return true;
}

bool net_GetHost(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName)
{
	if(net_GetHttpHost(buf,len,HostName,MaxHostName)==true)
	{
		return true;
	}
	if(net_GetHttpsHost(buf,len,HostName,MaxHostName)==true)
	{
		return true;
	}
	return false;
}

bool net_GetHttpsHost(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName)
{
    /* 1   TLS_HANDSHAKE_CONTENT_TYPE
     * 1   TLS major version
     * 1   TLS minor version
     * 2   TLS Record length
     * --------------
     * 1   Handshake type
     * 3   Length
     * 2   Version
     * 32  Random
     * 1   Session ID length
     * ?   Session ID
     * 2   Cipher Suites length
     * ?   Cipher Suites
     * 1   Compression Methods length
     * ?   Compression Methods
     * 2   Extensions length
     * ---------------
     * 2   Extension data length
     * 2   Extension type (0x0000 for server_name)
     * ---------------
     * 2   server_name list length
     * 1   server_name type (0)
     * 2   server_name length
     * ?   server_name
     */
    const int TLS_HEADER_LEN = 5;
    const int FIXED_LENGTH_RECORDS = 38;
    const int TLS_HANDSHAKE_CONTENT_TYPE = 0x16;
    const int TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    const uint8_t *data = buf;
    HostName[0] = '\0';
    int pos = 0;
    int length = len;

    if (length < TLS_HEADER_LEN + FIXED_LENGTH_RECORDS)
    {
    	log_error("Get HTTPS Host: not enough data");
        return false;
    }

    if ((data[0] & 0x80) && (data[2] == 1))
    {
    	log_error("SSL 2.0, does not support SNI");
        return false;
    }
    if (data[0] != TLS_HANDSHAKE_CONTENT_TYPE)
    {
        return false;
    }
    if (data[1] < 3)
    {
    	log_error("TLS major version < 3, does not support SNI");
        return false;
    }

    int record_len = (data[3] << 8) + data[4] + TLS_HEADER_LEN;
    if (length < record_len)
    {
    	log_error("Get HTTPS Host: not enough data");
    	return false;
    }
    if (data[TLS_HEADER_LEN] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    {
    	log_error("HTTPS Host: invalid handshake type");
        return false;
    }
    pos += TLS_HEADER_LEN + FIXED_LENGTH_RECORDS;

    // skip session ID
    if (pos + 1 > length || pos + 1 + data[pos] > length)
    {
    	log_error("Get HTTPS Host: not enough data");
    	return false;
    }
    pos += 1 + data[pos];
    // skip cipher suites
    if (pos + 2 > length || pos + 2 + (data[pos] << 8) + data[pos+1] > length)
    {
    	log_error("Get HTTPS Host: not enough data");
    	return false;
    }
    pos += 2 + (data[pos] << 8) + data[pos+1];
    // skip compression methods
    if (pos + 1 > length || pos + 1 + data[pos] > length)
    {
    	log_error("Get HTTPS Host: not enough data");
    	return false;
    }
    pos += 1 + data[pos];
    // skip extension length
    if (pos + 2 > length)
    {
       return false;
    }
    pos += 2;

        // parse extension data
    while (1)
    {
       if (pos + 4 > record_len)
       {
    	   log_error("buffer more than one record, SNI still not found");
          return false;
       }
       if (pos + 4 > length)
       {
    	   log_error("Get HTTPS Host: not enough data");
    	   return false;
       }
       int ext_data_len = (data[pos+2] << 8) + data[pos+3];
       if (data[pos] == 0 && data[pos+1] == 0)
       {
          // server_name extension type
          pos += 4;
          if (pos + 5 > length)
          {
        	 log_error("server_name list header");
             return false;
          }

          int server_name_len = (data[pos+3] << 8) + data[pos+4];
          if (pos + 5 + server_name_len > length)
          {
          	log_error("Get HTTPS Host: not enough data");
          	return false;
          }

          // return server_name
          if (server_name_len + 1 > MaxHostName)
          {
              return false;
          }

          memcpy(HostName, data + pos + 5, server_name_len);
          HostName[server_name_len] = '\0';
          return HostName;
        }
        else
        {
            // skip
            pos += 4 + ext_data_len;
        }
    }
}

bool net_GetHttpHost(uint8_t *buf,uint32_t len,char *HostName,uint16_t MaxHostName)
{
    const uint8_t *data = buf;
    HostName[0] = '\0';

    char *pos = (char *)MemSearch(buf, len, "\r\nHost:", 7/*strlen("\r\nHost:")*/);
    if (pos != NULL)
    {
        pos += 7;/*strlen("\r\nHost:")*/;
        while (*pos == ' ')
        {
            pos++;
        }

        len -= (int)(uint32_t)(pos - (char *)data);
        char *end_pos = (char *)MemSearch(pos, len, "\r\n", strlen("\r\n"));
        if (end_pos != NULL)
        {
            len = (int)(uint32_t)(end_pos - pos);
            if (len <= 0)
            {
                log_error("invalid Host in request");
                return false;
            }

            if (len + 1 > MaxHostName)
            {
                return false;
            }

            memcpy(HostName, pos, len);
            HostName[len] = '\0';
            return true;
        }
    }

    return false;
}

void *MemSearch(const void *haystack_start, size_t haystack_len,
        		const void *needle_start, size_t needle_len)
{
    /* Abstract memory is considered to be an array of 'unsigned char' values,
	   not an array of 'char' values.  See ISO C 99 section 6.2.6.1.  */
	const unsigned char *haystack = (const unsigned char *) haystack_start;
	const unsigned char *needle = (const unsigned char *) needle_start;


	/* The first occurrence of the empty string is deemed to occur at
	   the beginning of the string.  */
	if (needle_len == 0)
		return (void *) haystack;

	/* Sanity check, otherwise the loop might search through the whole memory.  */
	if (haystack_len < needle_len)
	    return NULL;

	const unsigned char *Startptr = (const unsigned char *)haystack_start;
	while(haystack_len)
	{
		haystack = memchr(haystack, *needle, haystack_len);
		if (!haystack || (needle_len == 1))
			return (void *) haystack;
		haystack_len -= haystack - Startptr;

		if (haystack_len < needle_len)
				return NULL;
		if (memcmp (haystack, needle, needle_len) == 0)
				return (void *) haystack;
		haystack++;
		haystack_len--;
		Startptr = haystack;
	}
	return NULL;
}

bool isTrueIpAddress(const char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

bool net_socket_timeout(int sockfd,int txTimeout,int rxTimeout)
{
    struct timeval xtimeout;      
    xtimeout.tv_sec = rxTimeout;
    xtimeout.tv_usec = 0;
    
    if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, &xtimeout, sizeof(xtimeout)) < 0)
    {
        return false;
    }
        
    xtimeout.tv_sec = txTimeout;
    if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, &xtimeout, sizeof(xtimeout)) < 0)
    {
        return false;
    }
    
    return true;
}