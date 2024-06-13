/*
 * statistics.h
 *
 *  Created on: Feb 17, 2020
 *      Author: zeus
 */

#ifndef STATISTICS_H_
#define STATISTICS_H_
#include <time.h>
#include <pthread.h>
#include <stdint.h>

typedef struct
{
	time_t 		StartTime;
	uint64_t	TotalRx;
	uint64_t	TotalTx;
	uint32_t 	TotalConnection;
	uint32_t	ActiveConnection;
	uint32_t	MaxConnection;
}stat_t;

typedef struct
{
	/*variable*/
	stat_t stat;
	char   name[128];
	/*thered lock*/
	pthread_mutex_t Lock;
	void *next;
}statistics_t;


void state_init(statistics_t **self,char *name);

void state_RxTxClose(statistics_t *self,uint32_t rx,uint32_t tx);
void state_IncConnection(statistics_t *self);

void state_get(statistics_t *self,stat_t *st);

#endif /* STATISTICS_H_ */
