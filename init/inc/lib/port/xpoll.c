/**********************************************************************
 * File : xpoll.c
 * Copyright (c) 0x75657573.
 * Created On : Tue Nov 28 2023
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 **********************************************************************/
#include "xpoll.h"
#include <stdlib.h>
#include <unistd.h> 
#include <string.h>
#include <log/log.h>

#define magic_x 0x7a657573

xpoll_t *xpoll_create(void)
{
    xpoll_t *poll = malloc(sizeof(xpoll_t));
    if(!poll)
        return NULL;
    memset(poll,0,sizeof(xpoll_t));

    // try make epoll handel
    poll->poll_fd = epoll_create1(0);
    
    // check epoll handel
    if (poll->poll_fd == -1) 
    {
		free(poll);
		return NULL;
	}

    return poll;
}

void xpoll_close(xpoll_t *poll)
{
    if(!poll)
        return;

    close(poll->poll_fd);
    free(poll);
}

xevent_t *xpoll_start_watch(xpoll_t *poll,int fd,poll_calback cb,void *userdata,x_event_t ev_type)
{
    /*make event*/
    xevent_t *event = (xevent_t*)malloc(sizeof(xevent_t));
    if(!event)
        return NULL;
    memset(event,0,sizeof(xevent_t));

    /*make user callection*/
    xuser_t *usr_ptr =(xuser_t*)malloc(sizeof(xuser_t));
    if(!usr_ptr)
    {
        free(event);
        return NULL;
    }
    memset(usr_ptr,0,sizeof(usr_ptr));
    
    /*set up user data*/
    usr_ptr->magic = magic_x;
    usr_ptr->fd = fd;
    usr_ptr->cb = cb;
    usr_ptr->data = userdata;

    /*set event paramiter*/
    event->events = ev_type;
    event->data.ptr = (void *)usr_ptr;

    if(epoll_ctl(poll->poll_fd, EPOLL_CTL_ADD, fd, event))
    {
        free(usr_ptr);
        free(event);
        return NULL;
    }

    return event;
}

bool xpoll_stop_watch(xpoll_t *poll,xevent_t *ev,int fd)
{
    if(!ev)
        return false;
    
    if(epoll_ctl(poll->poll_fd, EPOLL_CTL_DEL, fd, ev))
    {
        return false;
    }
    memset(ev->data.ptr,0,sizeof(xuser_t));
    free(ev->data.ptr);
    free(ev);
    return true;
}


void xpoll_run(xpoll_t *poll)
{
#define MAX_EVENTS 10
    xevent_t events[MAX_EVENTS] = {0};
    int event_count = epoll_wait(poll->poll_fd, events, MAX_EVENTS, 30000);
    for (int i = 0; i < event_count; i++) 
    {
        xevent_t *ev = &events[i];
        if(ev->data.ptr)
        {
            xuser_t *usr = (xuser_t*)ev->data.ptr;
            if(usr->magic!=magic_x)
            {
                log_error("########################-------------------> %d",ev->data.ptr);
                continue;
            }
            usr->cb(poll,usr->fd,usr->data);
        }
    }
}