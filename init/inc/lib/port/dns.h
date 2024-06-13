/**********************************************************************
 * File : dns.h
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
#ifndef dns_H
#define dns_H
#include <stdint.h>
#include <stdbool.h>

#define QR_MASK     0x8000
#define OPCODE_MASK 0x7800
#define AA_MASK     0x0400
#define TC_MASK     0x0200
#define RD_MASK     0x0100
#define RA_MASK     0x8000
#define RCODE_MASK  0x000F

/* Response Type */
enum 
{
  Ok_ResponseType = 0,
  FormatError_ResponseType = 1,
  ServerFailure_ResponseType = 2,
  NameError_ResponseType = 3,
  NotImplemented_ResponseType = 4,
  Refused_ResponseType = 5
};

/* Resource Record Types */
/*https://en.wikipedia.org/wiki/List_of_DNS_record_types*/
enum 
{
  A_Resource_RecordType = 1,
  NS_Resource_RecordType = 2,
  CNAME_Resource_RecordType = 5,
  SOA_Resource_RecordType = 6,
  PTR_Resource_RecordType = 12,
  MX_Resource_RecordType = 15,
  TXT_Resource_RecordType = 16,
  AAAA_Resource_RecordType = 28,
  SRV_Resource_RecordType = 33,
  HTTPS_Resource_RecordType = 65,
  SVCB_Resource_RecordType = 64
};

/* Operation Code */
enum 
{
  QUERY_OperationCode = 0, /* standard query */
  IQUERY_OperationCode = 1, /* inverse query */
  STATUS_OperationCode = 2, /* server status request */
  NOTIFY_OperationCode = 4, /* request zone transfer */
  UPDATE_OperationCode = 5 /* change resource records */
};

/* Response Code */
enum 
{
  NoError_ResponseCode = 0,
  FormatError_ResponseCode = 1,
  ServerFailure_ResponseCode = 2,
  NameError_ResponseCode = 3
};

/* Query Type */
enum 
{
  IXFR_QueryType = 251,
  AXFR_QueryType = 252,
  MAILB_QueryType = 253,
  MAILA_QueryType = 254,
  STAR_QueryType = 255
};

/* Question Section */
struct Question 
{
  char      *qName;
  uint16_t qType;
  uint16_t qClass;
  struct Question *next; // for linked list
};

/* Data part of a Resource Record */
union ResourceData 
{
  struct 
  {
    uint8_t txt_data_len;
    char *txt_data;
  } txt_record;
  struct 
  {
    uint8_t addr[4];
  } a_record;
  struct 
  {
    uint8_t addr[16];
  } aaaa_record;
};

/* Resource Record Section */
struct ResourceRecord {
  char *name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rd_length;
  union ResourceData rd_data;
  struct ResourceRecord *next; // for linked list
};

struct Message 
{
  uint16_t id; /* Identifier */

  /* Flags */
  uint16_t qr; /* Query/Response Flag */
  uint16_t opcode; /* Operation Code */
  uint16_t aa; /* Authoritative Answer Flag */
  uint16_t tc; /* Truncation Flag */
  uint16_t rd; /* Recursion Desired */
  uint16_t ra; /* Recursion Available */
  uint16_t rcode; /* Response Code */

  uint16_t qdCount; /* Question Count */
  uint16_t anCount; /* Answer Record Count */
  uint16_t nsCount; /* Authority Record Count */
  uint16_t arCount; /* Additional Record Count */

  /* At least one question; questions are copied to the response 1:1 */
  struct Question *questions;

  /*
  * Resource records to be send back.
  * Every resource record can be in any of the following places.
  * But every place has a different semantic.
  */
  struct ResourceRecord *answers;
  struct ResourceRecord *authorities;
  struct ResourceRecord *additionals;
};

/*
* Deconding/Encoding functions.
*/
/*decode dns message*/
bool dns_decode_msg(struct Message *msg, const uint8_t *buffer, int size);
bool dns_encode_msg(struct Message *msg, uint8_t **buffer);

/*free dns message struct*/
void free_msg(struct Message *msg);

#endif /* dns.h */
