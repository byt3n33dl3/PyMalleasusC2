/**********************************************************************
 * File : fifo.c
 * Copyright (c) Zeus@Sisoog.com.
 * Created On : Tue Apr 26 2022
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
#include <fifo.h>
#include <string.h>


bool fifo_init(fifo_t *self,uint16_t MessageSize,uint16_t ItemNumber)
{
	if(!self)
		return false;
		
	if(fifo_CreateMutex(self->Mutex_Id)!=0)
		return false;

	self->MessageSize = MessageSize;
	self->MessageItem = ItemNumber;
	self->Buffer = fifo_maloc(MessageSize*ItemNumber);
	self->wr_index = 0;
	self->rd_index = 0;
	self->counter = 0;
	
	if(self->Buffer==0)
	{
		return false;
	}
	return true;
}

void fifo_Remove(fifo_t *self)
{
	if(self==NULL)
		return;

	if(self->Buffer)
		fifo_free(self->Buffer);
	if(self)
		fifo_free(self);
}

bool fifo_incert(fifo_t *self,void *data)
{
	if(self==NULL)
		return false;

	fifo_lock(self->Mutex_Id);

	if (self->counter == self->MessageItem)
	{
		  fifo_unlock(self->Mutex_Id);
		  return false;
	}

	fifo_memcpy(&self->Buffer[self->wr_index*self->MessageSize],data,self->MessageSize);
	self->wr_index++;

   	if (self->wr_index == self->MessageItem) self->wr_index=0;
   		self->counter++;

   fifo_unlock(self->Mutex_Id);
   return true;
}

bool fifo_Read(fifo_t *self,void *data)
{
	if(self==NULL)
		return false;

	fifo_lock(self->Mutex_Id);

	if (self->counter == 0)
	{
	  fifo_unlock(self->Mutex_Id);
	  return false;
	}

	fifo_memcpy(data,&self->Buffer[self->rd_index*self->MessageSize],self->MessageSize);
	self->rd_index++;
	if (self->rd_index == self->MessageItem) self->rd_index=0;
	--self->counter;
	fifo_unlock(self->Mutex_Id);
	return true;
}

void fifo_flush(fifo_t *self)
{
	if(self==NULL)
		return;

	fifo_lock(self->Mutex_Id);
	fifo_memset(self->Buffer,0, self->MessageSize*self->MessageItem);
	self->wr_index = 0;
	self->rd_index = 0;
	self->counter = 0;
	fifo_unlock(self->Mutex_Id);
}

uint16_t fifo_UnreadMessage(fifo_t *self)
{
	if(self==NULL)
		return 0;
	uint16_t unread = 0;
	fifo_lock(self->Mutex_Id);
	unread = self->counter;
	fifo_unlock(self->Mutex_Id);
	return unread;
}

uint16_t fifo_SpacesAvailable(fifo_t *self)
{
	if(self==NULL)
		return 0;
	uint16_t Free = 0;
	fifo_lock(self->Mutex_Id);
	Free = self->MessageItem - self->counter;
	fifo_unlock(self->Mutex_Id);
	return Free;
}
