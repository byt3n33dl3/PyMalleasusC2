/*
 * SniProxy.c
 *
 *  Created on: Jan 28, 2020
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
#include "net.h"
#include <arpa/inet.h>
#include <errno.h>
#include <xpoll.h>

static void sni_accept_cb(xpoll_t *poll,int fd,void *user_ptr);
static void sni_read_cb(xpoll_t *poll,int fd,void *user_ptr);

bool SniProxy_Start(xpoll_t *eloop,SniServer_t *Sni)
{
	int sockfd;
	in_addr_t host_ip = inet_addr(Sni->Port.bindip);
	if(net_ListenIp4(host_ip, Sni->Port.local_port,&sockfd)==false)
	{
		log_error("can not listen on Port %s:%i",Sni->Port.bindip,Sni->Port.local_port);
		return false;
	}

	log_info("socket listen on %s:%d",Sni->Port.bindip,Sni->Port.local_port);
	SniServer_t *xsni = (SniServer_t*)malloc(sizeof(SniServer_t));
	if(!xsni)
	{
		log_error("can not make clone sni config");
		return false;
	}
	*xsni = *Sni;
	// Initialize and start a watcher to accepts client requests
	xevent_t *e = xpoll_start_watch(eloop,sockfd,sni_accept_cb ,(void*)xsni,xEPOLLIN | xEPOLLET);

	return true;
}

static inline void close_server_client(xpoll_t *poll,server_t *ptr)
{
	SniServer_t *config = &ptr->sni_config;
	sni_link_t	*sni_data = &ptr->sni_data;
	sni_ctx_t *user = &ptr->user;
	sni_ctx_t *server = &ptr->server;
	
	
	if(sni_data->is_sni_mark)
	{
		log_info("SNI end Host 0x%X:{ %s } txrx(%i/%i)",(uintptr_t)ptr,sni_data->hostname,user->total_rx,server->total_rx);

		/*Update statistics*/
		if(config->sta)
			state_RxTxClose(config->sta,server->total_rx,user->total_rx);
	}
	else
	{
		log_info("XXXXXXXXXXXXXXX end 0x%X: c/s(%i/%i)",(uintptr_t)ptr,user->total_rx,server->total_rx);
	}

	// close origin socket
	if(server->ev)
	{
		int socket = server->fd;
		// Stop and free watchet if client socket is closing
		if(xpoll_stop_watch(poll,server->ev,socket)==false)
		{
			log_error("server xpoll can not stop socket %d",socket);
		}
		close(socket);
	}
	
	if(user->ev)
	{
		int socket = user->fd;
		// Stop and free watchet if client socket is closing
		if(xpoll_stop_watch(poll,user->ev,socket)==false)
		{
			log_error("user xpoll can not stop socket %d",socket);
		}
		close(socket);
	}

	memset(ptr,0,sizeof(server_t));
	free(ptr);
}

/* Accept client requests */
static void sni_accept_cb(xpoll_t *poll,int fd,void *user_ptr)
{
	SniServer_t *sni_config = (SniServer_t*)user_ptr;

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	
	// Accept client request
	int client_sd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if (client_sd < 0)
	{
		log_error("accept error %d",client_sd);
		return;
	}

	server_t *ptr = malloc(sizeof(server_t));
	memset(ptr,0,sizeof(server_t));
	ptr->sni_config = *sni_config;
	
	state_IncConnection(sni_config->sta);
	
	// Initialize and start watcher to read client requests
	ptr->user.total_rx = 0;
	ptr->user.fd = client_sd;
	ptr->user.ev = xpoll_start_watch(poll,client_sd,sni_read_cb ,(void*)ptr, xEPOLLIN | xEPOLLET);
	if(!ptr->user.ev)
	{
		log_error("xpoll: can not make read event poll");
	}

	// Convert the binary IPv4 address to a string
	char ip[INET_ADDRSTRLEN]; // Buffer for the IP address
    if (inet_ntop(AF_INET, &(client_addr.sin_addr), ip, INET_ADDRSTRLEN) != NULL) 
	{
        log_info("SNI incoming connection 0x%X from %s:%d", (uintptr_t)ptr, ip,ntohs(client_addr.sin_port));
    }
}

static void sni_origin_read_cb(xpoll_t *poll,int fd,void *user_ptr)
{
	server_t *ptr = (server_t*)user_ptr;
	sni_ctx_t *server = &ptr->server;

	char buffer[SNI_BUFFER_SIZE];
	ssize_t read;
	
	// Receive message from server socket
	read = recv(fd, buffer, SNI_BUFFER_SIZE, 0);

	if(read <= 0)
	{
		close_server_client(poll,ptr);
		return;
	}

	server->total_rx += read;
	sni_ctx_t *user = &ptr->user;
	// Send message bach to the origin server
	if(send(user->fd, buffer, read, MSG_NOSIGNAL)!=read)
	{
		log_error("Can not write to socket.....");
		close_server_client(poll,ptr);
	}
}

static void sni_read_cb(xpoll_t *poll,int fd,void *user_ptr)
{
	server_t *ptr = (server_t*)user_ptr;
	sni_ctx_t *user = &ptr->user;

	char buffer[SNI_BUFFER_SIZE]={0};
	ssize_t read;
// 	// Receive message from client socket
	read = recv(fd, buffer, SNI_BUFFER_SIZE, 0);

	if(read <= 0)
	{
		close_server_client(poll,ptr);
		return;
	}

	user->total_rx += read;

	sni_link_t *sni_data = &ptr->sni_data;
	SniServer_t *config = &ptr->sni_config;
	/*is found sni ?*/
	if(sni_data->is_sni_mark!=true)
	{	
		/*check buffer overflow*/
		if(read+sni_data->w_index >= MAX_SNI_PACKET)
		{
			log_error("sni packet Buffer OverFlow!");
			close_server_client(poll,ptr);
			return;
		}

		//copy data to buffer
		memcpy(sni_data->sni_packet+sni_data->w_index,buffer,read);
		sni_data->w_index += read;

		if(net_GetHost(sni_data->sni_packet,sni_data->w_index,sni_data->hostname,_MaxHostName_))
		{
			/*Check host validate*/
			if(config->wlist && filter_IsWhite(config->wlist,sni_data->hostname)==false)
			{
				log_info("SNI filter Host { %s }",sni_data->hostname);
				close_server_client(poll,ptr);
				return;
			}

			if(isTrueIpAddress(sni_data->hostname))
			{
				log_info("SNI we can't support IP address");
				close_server_client(poll,ptr);
				return;
			}

			log_info("SNI start Host 0x%X:{ %s }",(uintptr_t)ptr,sni_data->hostname);
			sni_data->is_sni_mark = true;

			sockshost_t *socks = config->Socks;
			lport_t 	xport = config->Port;
			int server_socket = 0;
			if(socks)	/*Set Connect to socks*/
			{
				if(!socks5_connect(&server_socket,socks,sni_data->hostname,xport.remote_port,false))
				{
					close_server_client(poll,ptr);
					return;
				}
			}
			else	/*connect directly*/
			{
				if(!net_connect(&server_socket,sni_data->hostname,xport.remote_port))
				{
					close_server_client(poll,ptr);
					return;
				}
			}
			
			sni_ctx_t *server = &ptr->server;
			// Initialize and start watcher to read client requests
			server->fd = server_socket;
			server->total_rx = 0;
			server->ev = xpoll_start_watch(poll,server_socket,sni_origin_read_cb ,(void*)ptr, xEPOLLIN | xEPOLLET);
			if(!server->ev)
			{
				log_error("xpoll: can not make read event poll");
				close_server_client(poll,ptr);
				return;
			}

			/*Send sni packet to origin server*/
			if(send(server_socket,sni_data->sni_packet,sni_data->w_index,MSG_NOSIGNAL)!=sni_data->w_index)
			{
				close_server_client(poll,ptr);
				return;
			}
			return;
		}
		else
		{
			log_error("SNI NotFound @0x%X buffer len %d",(uintptr_t)ptr,sni_data->w_index);
		}
	}

	sni_ctx_t *server = &ptr->server;
	// Send message bach to the origin server
	if(send(server->fd, buffer, read, MSG_NOSIGNAL)!=read)
	{
		log_error("Can not write to socket...");
		close_server_client(poll,ptr);
	}
}