/*
 * monitor.c
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "monitor.h"
#include "log/log.h"
#include "net.h"
#include <inttypes.h>

void *Monitor_HandleConnection(void *vargp);
void Conv_Time(time_t Up,UpTime_t *tm);
char *Print_humanSize(char *ptr,uint64_t bytes);

mon_t *monitor_Init(uint16_t *Port)
{
	int sockfd;

	if(net_ListenIp4(htonl(INADDR_ANY), *Port,&sockfd)==false)
	{
		log_error("monitor can not listen on Port %i",*Port);
		return NULL;
	}

	log_info("monitor listen on %d",*Port);
	mon_t	*mon = malloc(sizeof(mon_t));
	mon->state = NULL;
	//state_init(&mon->state);		/*create statistics var*/
	mon->fd = sockfd;
	mon->Port = *Port;

	pthread_t thread_id;
	pthread_create(&thread_id, NULL, Monitor_HandleConnection, (void*)mon);
	//pthread_join(thread_id, NULL);

	return mon;
}

statistics_t *monitor_AddNewStat(mon_t *self,char *name)
{
	statistics_t *stat = self->state;
	state_init(&self->state,name);		/*create statistics var*/
	self->state->next = stat;
	return self->state;
}

void *Minitor_HandelConnection(void *arg);
void Monitor_HandelClient(int fd,uint8_t *data,int len,statistics_t *sta);
void *Monitor_HandleConnection(void *vargp)
{
	mon_t *mon = (mon_t*)vargp;
	int sockfd = mon->fd;	  /* listening socket descriptor */

	log_info("Monitor thread start on socket %i Port %d",sockfd,mon->Port);
	monclient_t *client;
	while(1)
	{
		client = (monclient_t *)malloc(sizeof(monclient_t));
		client->connid = accept(sockfd, (struct sockaddr*)&client->cli, &client->addr_len);
		client->state = mon->state;
		if (client->connid < 0)
		{
			free(client);
			log_error("server accept failed");
			continue;
		}

		pthread_t thread_id;
		pthread_create(&thread_id, NULL, Minitor_HandelConnection, (void*)client);
		pthread_detach(thread_id);
	}
}

void *Minitor_HandelConnection(void *arg)
{
	if (!arg) pthread_exit(0);
	monclient_t *client = (monclient_t*)arg;
	uint8_t buffer[0x4000]; /*16Kb memory tmp*/
	uint32_t Windex = 0;

	fd_set rfds;
	struct timeval tv;
	while(1)
	{
		FD_ZERO(&rfds);
		tv.tv_sec = 30;
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
		Windex+=newData;

		Monitor_HandelClient(client->connid,buffer,Windex,client->state);
		break;
	}

	log_info("Monitor tid:%i Prosess",client->connid);
	close(client->connid);
	free(client);
	pthread_exit(0);
	return NULL;
}

/*https://www.tutorialspoint.com/http/http_message_examples.htm*/
void Monitor_HandelClient(int fd,uint8_t *data,int len,statistics_t *stat)
{
	char message[2048] = {0};
	char *ptr = message;

	statistics_t *sta = stat;
	while(sta)
	{
		/*incoming data and possess it*/
		stat_t stdata;
		state_get(sta,&stdata);	/*get static data*/
		time_t CurrentTime;
		time ( &CurrentTime );
		time_t LiveTime = CurrentTime - stdata.StartTime;
		UpTime_t lt;
		Conv_Time(LiveTime,&lt);

		ptr += sprintf(ptr,"<h1>%s</h1> </br>",sta->name);
		ptr += sprintf(ptr,"Up Time: %i days, %i:%i:%i </br>", lt.tm_yday,lt.tm_hour,lt.tm_min,lt.tm_sec);
		ptr += sprintf(ptr,"Max Connection : %i</br>",stdata.MaxConnection);
		ptr += sprintf(ptr,"Active Connection : %i</br>",stdata.ActiveConnection);
		ptr += sprintf(ptr,"Total Connection : %i</br>",stdata.TotalConnection);

		ptr += sprintf(ptr,"Total Rx : ");
		ptr = Print_humanSize(ptr,stdata.TotalRx);
		ptr += sprintf(ptr,"</br>");
		ptr += sprintf(ptr,"Total Tx : ");
		ptr = Print_humanSize(ptr,stdata.TotalTx);
		ptr += sprintf(ptr,"</br></br>");

		sta = (statistics_t*)sta->next;
	}





	char httpMessage[8000];
	int slen = sprintf(httpMessage,"HTTP/1.1 200 OK\nContent-Type: text/html; charset=UTF-8\nContent-Length: %i\nConnection: Closed\n\n%s",(int)(ptr-message),message);
	write(fd,httpMessage,slen);	/*echo*/
}



void Conv_Time(time_t Up,UpTime_t *tm)
{
#define OneDaySec	(3600*24)

	tm->tm_yday = Up/OneDaySec;
	time_t Rtime = Up%OneDaySec;
	tm->tm_hour = Rtime/3600;
	Rtime = Rtime%3600;
	tm->tm_min = Rtime/60;
	tm->tm_sec = Rtime%60;
}

char *Print_humanSize(char *ptr,uint64_t bytes)
{
	char *suffix[] = {"B", "KB", "MB", "GB", "TB"};
	char length = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double dblBytes = bytes;

	if (bytes >= 1024)
	{
		for (i = 0; (bytes / 1024) > 0 && i<length-1; i++, bytes /= 1024)
			dblBytes = bytes / 1024.0;
	}

	ptr += sprintf(ptr, "%.02lf %s", dblBytes, suffix[i]);
	return ptr;
}
