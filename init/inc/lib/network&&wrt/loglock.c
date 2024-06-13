/*
 * loglock.c
 *
 *  Created on: Jan 30, 2020
 *      Author: zeus
 */
#include <pthread.h>
#include "log.h"
#include <stdlib.h>

pthread_mutex_t LogLock;

static void lock_callback(void *udata, int lock)
{
  if (lock)
  {
	  pthread_mutex_lock(udata);
  }
  else
  {
	  pthread_mutex_unlock(udata);
  }
}


void Log_init(void)
{
	if (pthread_mutex_init(&LogLock, NULL) != 0)
	{
	    log_error("mutex init has failed");
	    exit(0);
	}

	log_set_udata(&LogLock);
	log_set_lock(lock_callback);
}
