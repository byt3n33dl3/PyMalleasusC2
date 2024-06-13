/**********************************************************************
 * File : dns.c
 * Copyright (c) Zeus@Sisoog.com.
 * Created On : Tue Apr 26 2022
 * based on https://github.com/mwarning/SimpleDNS
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
#include <stdlib.h>
#include <stdint.h>
#include <config.h>
#include <string.h>
#include "dns.h"
#include <log/log.h>
#include <arpa/inet.h>

#define MIN(x, y) ((x) <= (y) ? (x) : (y))
/*
* Basic memory operations.
*/
static void put8bits(uint8_t **buffer, uint8_t value)
{
  *(*buffer)++=value;
}

static size_t get16bits(const uint8_t **buffer)
{
  uint16_t value;
  value  = (*(*buffer)++)<<8 ;
  value |= *(*buffer)++;
  return value;
}

static void put16bits(uint8_t **buffer, uint16_t value)
{
  *(*buffer)++ = value>>8;
  *(*buffer)++ = value&0xFF;
}

static void put32bits(uint8_t **buffer, uint32_t value)
{
  *(*buffer)++ = (value>>24)&0xFF;
  *(*buffer)++ = (value>>16)&0xFF;
  *(*buffer)++ = (value>> 8)&0xFF;
  *(*buffer)++ = (value>> 0)&0xFF;
}

// 3foo3bar3com0 => foo.bar.com (No full validation is done!)
char *decode_domain_name(const uint8_t **buf, size_t len)
{
  /*find end if name*/
  int domain_len = 0;
  for(size_t i=0;i<len;i++)
    if((*buf)[i]==0)
    {
      domain_len = i+1;
      break;
    }  

  char domain[_MaxHostName_];
  for (int i = 1; i < MIN(_MaxHostName_, domain_len); i++) 
  {
    uint8_t c = (*buf)[i];
    if (c == 0) 
    {
      domain[i - 1] = 0;
      *buf += i + 1;
      return strdup(domain);
    } 
    else if (c <= 63 && c <= (domain_len-i)) 
    {
      domain[i - 1] = '.';
    } 
    else 
    {
      domain[i - 1] = c;
    }
  }
  return NULL;
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uint8_t **buffer, const char *domain)
{
  uint8_t *buf = *buffer;
  const char *beg = domain;
  const char *pos;
  int len = 0;
  int i = 0;

  while ((pos = strchr(beg, '.'))) 
  {
    len = pos - beg;
    buf[i++] = len;
    memcpy(buf+i, beg, len);
    i += len;

    beg = pos + 1;
  }

  len = strlen(domain) - (beg - domain);

  buf[i++] = len;

  memcpy(buf + i, beg, len);
  i += len;

  buf[i++] = 0;

  *buffer += i;
}

void dns_decode_header(struct Message *msg, const uint8_t **buffer)
{
  msg->id = get16bits(buffer);

  uint32_t fields = get16bits(buffer);
  msg->qr = (fields & QR_MASK) >> 15;
  msg->opcode = (fields & OPCODE_MASK) >> 11;
  msg->aa = (fields & AA_MASK) >> 10;
  msg->tc = (fields & TC_MASK) >> 9;
  msg->rd = (fields & RD_MASK) >> 8;
  msg->ra = (fields & RA_MASK) >> 7;
  msg->rcode = (fields & RCODE_MASK) >> 0;

  msg->qdCount = get16bits(buffer);
  msg->anCount = get16bits(buffer);
  msg->nsCount = get16bits(buffer);
  msg->arCount = get16bits(buffer);
}

void dns_encode_header(struct Message *msg, uint8_t **buffer)
{
  put16bits(buffer, msg->id);

  int fields = 0;
  fields |= (msg->qr << 15) & QR_MASK;
  fields |= (msg->rcode << 0) & RCODE_MASK;
  // TODO: insert the rest of the fields
  put16bits(buffer, fields);

  put16bits(buffer, msg->qdCount);
  put16bits(buffer, msg->anCount);
  put16bits(buffer, msg->nsCount);
  put16bits(buffer, msg->arCount);
}

bool dns_decode_msg(struct Message *msg, const uint8_t *buffer, int size)
{
  dns_decode_header(msg, &buffer);

  if (msg->anCount != 0 || msg->nsCount != 0) 
  {
    log_error("Only questions expected!");
    return false;
  }

  // parse questions
  uint32_t qcount = msg->qdCount;
  for (int i = 0; i < qcount; ++i) 
  {
    struct Question *q = malloc(sizeof(struct Question));

    q->qName = decode_domain_name(&buffer, size);
    q->qType = get16bits(&buffer);
    q->qClass = get16bits(&buffer);

    if (q->qName == NULL) 
    {
      log_error("Failed to decode domain name!");
      return false;
    }

    // prepend question to questions list
    q->next = msg->questions;
    msg->questions = q;
  }

  // We do not expect any resource records to parse here.
  return true;
}

void free_questions(struct Question *qq)
{
  struct Question *next;
  while (qq) 
  {
    free(qq->qName);
    next = qq->next;
    free(qq);
    qq = next;
  }
}

void free_resource_records(struct ResourceRecord *rr)
{
  struct ResourceRecord *next;
  while (rr) 
  {
    free(rr->name);
    next = rr->next;
    free(rr);
    rr = next;
  }
}

void free_msg(struct Message *msg)
{
  free_questions(msg->questions);
  free_resource_records(msg->answers);
  free_resource_records(msg->authorities);
  free_resource_records(msg->additionals);
  memset(msg, 0, sizeof(struct Message));
}

/* @return 0 upon failure, 1 upon success */
int encode_resource_records(struct ResourceRecord *rr, uint8_t **buffer)
{
  int i;
  while (rr) {
    // Answer questions by attaching resource sections.
    encode_domain_name(buffer, rr->name);
    put16bits(buffer, rr->type);
    put16bits(buffer, rr->class);
    put32bits(buffer, rr->ttl);
    put16bits(buffer, rr->rd_length);

    switch (rr->type) {
      case A_Resource_RecordType:
        for (i = 0; i < 4; ++i)
          put8bits(buffer, rr->rd_data.a_record.addr[i]);
        break;
      case AAAA_Resource_RecordType:
        for (i = 0; i < 16; ++i)
          put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
        break;
      case TXT_Resource_RecordType:
        put8bits(buffer, rr->rd_data.txt_record.txt_data_len);
        for (i = 0; i < rr->rd_data.txt_record.txt_data_len; i++)
          put8bits(buffer, rr->rd_data.txt_record.txt_data[i]);
        break;
      default:
        fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
      return 1;
    }

    rr = rr->next;
  }

  return 0;
}

bool dns_encode_msg(struct Message *msg, uint8_t **buffer)
{
  struct Question *q;
  int rc;

  dns_encode_header(msg, buffer);

  q = msg->questions;
  while (q) 
  {
    encode_domain_name(buffer, q->qName);
    put16bits(buffer, q->qType);
    put16bits(buffer, q->qClass);

    q = q->next;
  }

  rc = 0;
  rc |= encode_resource_records(msg->answers, buffer);
  rc |= encode_resource_records(msg->authorities, buffer);
  rc |= encode_resource_records(msg->additionals, buffer);

  return rc==0;
}