/*
 * statistics.c
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */
#include "statistics.h"
#include <log/log.h>
#include <stdlib.h>
#include <string.h>


void state_init(statistics_t **self,char *name)
{
	*self = malloc(sizeof(statistics_t));
	memset(*self,0,sizeof(statistics_t));
	if(pthread_mutex_init(&(*self)->Lock, NULL) != 0)
	{
	    log_error("statistics mutex init has failed");
	    exit(0);
	}
	strcpy((*self)->name,name);
	time ( &(*self)->stat.StartTime );
	(*self)->next = NULL;
}


void state_RxTxClose(statistics_t *self,uint32_t rx,uint32_t tx)
{
	pthread_mutex_lock(&self->Lock);
	self->stat.TotalRx += rx;
	self->stat.TotalTx += tx;
	self->stat.ActiveConnection--;
	self->stat.TotalConnection++;
	pthread_mutex_unlock(&self->Lock);
}


void state_IncConnection(statistics_t *self)
{
	pthread_mutex_lock(&self->Lock);
	self->stat.ActiveConnection++;
	if(self->stat.ActiveConnection>self->stat.MaxConnection)
		self->stat.MaxConnection = self->stat.ActiveConnection;
	pthread_mutex_unlock(&self->Lock);
}

void state_get(statistics_t *self,stat_t *st)
{
	pthread_mutex_lock(&self->Lock);
	*st =  self->stat;
	pthread_mutex_unlock(&self->Lock);
}

