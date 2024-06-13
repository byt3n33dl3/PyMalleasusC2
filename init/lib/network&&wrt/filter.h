/*
 * filter.h
 *
 *  Created on: Mar 8, 2020
 *      Author: zeus
 */

#ifndef FILTER_FILTER_H_
#define FILTER_FILTER_H_
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <config.h>


typedef struct
{
	char Rec[_MaxHostName_];
	void *Next;
}item_t;

typedef struct
{
	char   *filepath; /*filter file path*/
	item_t *item;			/*start */
	pthread_mutex_t Lock;	/*thread lock*/
}filter_t;


filter_t *filter_init(char *filename);
bool filter_IsWhite(filter_t *self,char *host);
#endif /* FILTER_FILTER_H_ */
