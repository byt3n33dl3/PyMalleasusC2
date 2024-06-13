/**********************************************************************
 * File : xpoll.h
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
#ifndef xpoll_h
#define xpoll_h
#include <stdint.h>
#include <stdbool.h>
#include <sys/epoll.h>

typedef struct 
{
    int poll_fd;
} xpoll_t;

typedef void (*poll_calback)(xpoll_t *poll,int fd,void *user_ptr);

typedef struct 
{
    uint32_t     magic;
    int          fd;
    poll_calback cb;
    void        *data;
} xuser_t;

typedef struct epoll_event  xevent_t;

typedef enum
{
    xEPOLLIN = EPOLLIN,
    xEPOLLPRI = EPOLLPRI,
    xEPOLLOUT = EPOLLOUT,
    xEPOLLRDNORM = EPOLLRDNORM,
    xEPOLLRDBAND = EPOLLRDBAND,
    xEPOLLWRNORM = EPOLLWRNORM,
    xEPOLLWRBAND = EPOLLWRBAND,
    xEPOLLMSG = EPOLLMSG,
    xEPOLLERR = EPOLLERR,
    xEPOLLHUP = EPOLLHUP,
    xEPOLLRDHUP = EPOLLRDHUP,
    xEPOLLEXCLUSIVE = EPOLLEXCLUSIVE,
    xEPOLLWAKEUP = EPOLLWAKEUP,
    xEPOLLONESHOT = EPOLLONESHOT,
    xEPOLLET = EPOLLET
}x_event_t;



xpoll_t *xpoll_create(void);
void xpoll_close(xpoll_t *poll);

xevent_t *xpoll_start_watch(xpoll_t *poll,int fd,poll_calback cb,void *userdata,x_event_t ev_type);
bool xpoll_stop_watch(xpoll_t *poll,xevent_t *ev,int fd);

void xpoll_run(xpoll_t *poll);
#endif /* xpoll_h */
