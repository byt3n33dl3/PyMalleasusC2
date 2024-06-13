/*
 ============================================================================
 Name        : Zroxy.c
 Author      : Zeus
 Version     :
 Copyright   : Copyright 2020 Mohammad Mazarei This program is free software
 Description : simple and smart sni-proxy.
 ============================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> /*Lib Socket*/
#include <unistd.h>  	/*Header file for sleep(). man 3 sleep for details.*/
#include <pthread.h>
#include <log/log.h>
#include <sniproxy.h>
#include "version.h"
#include <netdb.h>		/* getaddrinfo, getnameinfo */ /*https://rosettacode.org/wiki/DNS_query#C*/
#include <stdbool.h>
#include "args.h"
#include <monitor.h>
#include "filter/filter.h"
#include <xpoll.h>
#include <signal.h>

zroxy_t prg_setting = {0};

/*ignore the SIGPIPE signal.*/
static void ignore_sigign(void)
{
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGPIPE, &sa, 0);
}

/*
 * for test dns server
 * dig @127.0.0.1 google.com -p5656
 *
 * about tcp/ip and socket in c:
 * https://www.csd.uoc.gr/~hy556/material/tutorials/cs556-3rd-tutorial.pdf
 *
 * for Non Block IO:
 * https://www.gnu.org/software/libc/manual/html_node/Waiting-for-I_002fO.html
 * https://www.gnu.org/software/libc/manual/html_node/Server-Example.html
 * https://www.tenouk.com/Module41.html
 * */
int main(int argc, const char **argv)
{
	// ignore SIGPIPE
	ignore_sigign();

	if(arg_Init(&prg_setting,argc,argv)==false)
	{
		print_usage();
		exit(EXIT_FAILURE);
	}
	
	mon_t *monitor = NULL;
	// /*check Monitor*/
	// if(prg_setting.monitorPort)
	// {
	// 	log_info("enable monitor on port %i",*prg_setting.monitorPort);
	// 	monitor = monitor_Init(prg_setting.monitorPort);
	// }

	/*chack white list*/
	filter_t *whitelist = NULL;
	// if(prg_setting.WhitePath)
	// {
	// 	log_info("load white list from %s",prg_setting.WhitePath);
	// 	whitelist = filter_init(prg_setting.WhitePath);
	// 	free(prg_setting.WhitePath);
	// }

	xpoll_t *e_poll = xpoll_create();
	if(!e_poll)
	{
		log_error("cannot initialize epoll.");
		exit(EXIT_FAILURE);
	}

	// /*check for dns server*/
	// if(prg_setting.dnsserver)
	// {
	// 	if(monitor)
	// 		prg_setting.dnsserver->Stat = monitor_AddNewStat(monitor,"DNS Server");
		
	// 	prg_setting.dnsserver->whitelist = whitelist;

	// 	log_info("start dns server ...");
	// 	dnsserver_init(prg_setting.dnsserver);
	// }

	lport_t *p=prg_setting.ports;
	statistics_t *SniStat = NULL;
	if(monitor)
		SniStat = monitor_AddNewStat(monitor,"SNI Server");

	SniServer_t Xconf = { /*.Port = {0},*/ .Socks = NULL ,.sta = SniStat ,.wlist = whitelist };
	/*if Set Socks proxy*/
	if(prg_setting.socks)
	{
		log_info("enable socks on %s:%i",prg_setting.socks->host,prg_setting.socks->port);
		Xconf.Socks = prg_setting.socks;
	}

	while(p)
	{
		Xconf.Port = *p;
		SniProxy_Start(e_poll,&Xconf);

		p=p->next;
	}
	Free_PortList(&prg_setting); /*free Port List*/

	// Start infinite loop
	while (1)
	{
		xpoll_run(e_poll);
	}
	

	log_info("Exit zroxy");
	return EXIT_SUCCESS;
}

