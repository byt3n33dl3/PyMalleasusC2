/*
 * args.c
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */
#include "args.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "version.h"
#include <stdbool.h>
//#include <argp.h>
#include <log/log.h>
#include <netdb.h>
#include <getopt.h>
#include <ctype.h>

static char doc[] = "zroxy v"version "\n\tsimple sni and dns proxy.";
static int parse_opt(int key, char *arg, void *userprm);

void Parse_Ports(zroxy_t *ptr,char *str);
void Parse_Socks(zroxy_t *ptr,char *str);
void Parse_Monit(zroxy_t *ptr,char *str);
void Parse_whitelist(zroxy_t *ptr,char *str);
void Parse_DNSServer(zroxy_t *ptr,char *str);
void Parse_DnsUpstream(zroxy_t *ptr,char *str);
void Parse_DnsSocks(zroxy_t *ptr,char *str);
bool Parse_config(zroxy_t *ptr,char *str);
void Parse_Snip(zroxy_t *ptr,char *str);
void Parse_DNStimeout(zroxy_t *ptr,char *str);

typedef struct 
{
	const char *name;
	char 		key;
	const char  *arg;
	int			require;
	const char *doc;
}arg_option;


static arg_option options[] =
{
	{ "config", 'c' , "path to config" , required_argument, "path to config. -c /etc/zroxy.conf"},
    { "port", 'p', "sni port", required_argument, "sni port that listens.\n\t\t\t\t\t\t<bind ip>:<local port>@<remote port>\n\t\t\t\t\t\t -p 127.0.0.1:8080@80,4433@433,853..."},
	{ "socks", 's', "socks proxy", required_argument, "set proxy for up stream. -s 127.0.0.1:9050"},
	{ "monitor", 'm', "monitor port", required_argument, "monitor port that listens. -m 1234"},
	{ "white", 'w' , "white list" , required_argument, "white list for host -w /etc/withlist.txt"},
	{ "ldns", 'd' , "local DNS server" , required_argument, "dns server that listens. -d 0.0.0.0:53"},
	{ "dns", 'u' , "upstream DNS providers" , required_argument, "upstream DNS providers. -u 8.8.8.8"},
	{ "dsocks", 'x' , "DNS upstream socks" , required_argument, "DNS upstream socks. -x 127.0.0.1:9050"},
	{ "dtimeout", 't' , "DNS timeout in sec" , required_argument, "DNS upstream timeout. -t 5"},
	{ "snip", 'i' , "SNI IP for DNS server" , required_argument, "SNI IP for DNS server. -i 127.0.0.1"},
	{ "help", 'h' , "Give this help list" , no_argument, ""},
    { 0 }
};

void print_usage(void)
{
	
	printf("\r\nUsage: zroxy [OPTION...]\r\n");
	printf("\t%s\r\n\r\n",doc);

	int arg_number = sizeof(options)/sizeof(arg_option);
	for(int i=0;i<arg_number-1;i++)
	{
		printf("\t-%c, '%s'\t%s\t\t%s\r\n",
			options[i].key,
			options[i].name,
			options[i].arg,
			options[i].doc
		);
	}
	printf("\r\n");
}

bool arg_Init(zroxy_t *pgp,int argc, const char **argv)
{
	pgp->ports = NULL;
	/*ran without parameter*/
	if(argc==1) 
	{
		return Parse_config(pgp,DEF_CONFIG_PATH);
	}

	/*map arg_option to option*/
	int arg_number = sizeof(options)/sizeof(arg_option);
	struct option x_options[arg_number];
	bzero(x_options,sizeof(x_options));
	for(int i=0;i<arg_number;i++)
	{
		x_options[i].name = options[i].name;
		x_options[i].val = options[i].key;
		x_options[i].has_arg = options[i].require;
		x_options[i].flag = NULL;
	}	

	//make opt string
	char optstring[128] = {0};
	uint32_t index = 0;
	for(struct option *op=x_options;op->name!=NULL;op++)
	{
		optstring[index++]=op->val;
		if(op->has_arg==required_argument)
			optstring[index++]=':';
		else if(op->has_arg==optional_argument)
			optstring[index++]=';';

		/*check Overflow*/
		if(index>=sizeof(optstring)-1)
			break;
	}	

	int option_index = 0;
	while(1)
	{
		int key = getopt_long(argc, (char **)argv, optstring, x_options, &option_index);
		if (key == -1)
            break;
		
		if(parse_opt(key, optarg, pgp)!=0)
		{
			log_error("error invalid value in config: %s",key);
			return false;
		}
	}

    return true;
}

static int parse_opt(int key, char *arg, void *userprm)
{
	zroxy_t *setting = (zroxy_t*)userprm;

	/*remove space form arg*/
	if(arg)
		while(*arg==' ') arg++;

    switch (key)
    {
		case 'c': Parse_config(setting,arg); break;
		case 'p': Parse_Ports(setting,arg); break;
		case 's': Parse_Socks(setting,arg); break;
		case 'm': Parse_Monit(setting,arg); break;
		case 'w': Parse_whitelist(setting,arg); break;
		case 'd': Parse_DNSServer(setting,arg); break;
		case 'u': Parse_DnsUpstream(setting,arg); break;
		case 'x': Parse_DnsSocks(setting,arg); break;
		case 'i': Parse_Snip(setting,arg); break;
		case 't': Parse_DNStimeout(setting,arg); break;
		case 'h': print_usage(); exit(0);
		default: return -1;
    }
    return 0;
}

char *ltrim(char *s)
{
    while(isspace(*s)) s++;
    return s;
}

char *rtrim(char *s)
{
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}

char *trim(char *s)
{
    return rtrim(ltrim(s)); 
}

char* toLower(char* s) 
{
  for(char *p=s; *p; p++) *p=tolower(*p);
  return s;
}

bool validate_number(char *str)
{
   while (*str)
   {
	   //if the character is not a number, return false
      if(!isdigit(*str))
      {
         return false;
      }
      str++; //point to next character
   }
   return true;
}

//check whether the IP is valid or not
bool validate_ip(char *ip)
{
   int num=0, dots = 0;
   char *ptr;
   if (ip == NULL)
      return false;

   //cut the string using dor delimiter
   ptr = strtok(ip, ".");
   if (ptr == NULL)
      return false;

   while (ptr)
   {
	   num = -1;
	   //check whether the sub string is holding only number or not
      if(validate_number(ptr)==true)
    	  //convert substring to number
    	  num = atoi(ptr);


       if (num >= 0 && num <= 255)
       {
        	//cut the next part of the string
            ptr = strtok(NULL, ".");
            if (ptr != NULL)
               //increase the dot count
               dots++;
       }
       else
            return false;
    }

    //if the number of dots are not 3, return false
    if (dots != 3)
       return false;
      return true;
}

int config_find_key(char *key)
{
	for(arg_option *ptr=options;ptr->name!=NULL;ptr++)
	{
		if(strcmp(ptr->name,key)==0)
			return ptr->key;
	}
	return -1;
}

bool Parse_config(zroxy_t *ptr,char *str)
{
	while(*str==' ') str++; /*remove space*/
	FILE *ConfigFile  = fopen(str, "r"); // read only
	if(ConfigFile==NULL)
	{
		log_error("config file not found");
		return false;
	}

	/*read and load config from file*/
	bool ret_status = true;
	size_t len = 0;
	char *line = NULL;
	ssize_t read;
	
	while ((read = getline(&line, &len, ConfigFile)) != -1)
	{
		char key[100]={0};
		char val[100]={0};
		int xpars = sscanf(line,"%99[a-zA-Z_ ]=%99[@:_,/\\a-zA-Z.0-9 ]",key,val);
		if(xpars!=2)
			continue;
		char *fix_key = toLower(trim(key));
		char *fix_val = toLower(trim(val));

		int ckey = config_find_key(fix_key);
		if(ckey<0)
		{
			log_error("error invalid key in config: %s",fix_key);
			ret_status = false;
			break;
		}

		if(parse_opt(ckey, fix_val, ptr)!=0)
		{
			log_error("error invalid value in config: %s",fix_val);
			ret_status = false;
			break;
		}
	}

	free(line);
	fclose(ConfigFile);
	return ret_status;
}

void Parse_whitelist(zroxy_t *ptr,char *str)
{
	while(*str==' ') str++; /*remove space before path*/
	ptr->WhitePath = strdup(str);
}

void Parse_Monit(zroxy_t *ptr,char *str)
{
	ptr->monitorPort = (uint16_t*)malloc(sizeof(uint16_t));
	*ptr->monitorPort = atol(str);
}

void Parse_DNStimeout(zroxy_t *ptr,char *str)
{
	if(!ptr->dnsserver)
	{
		log_error("before set dns timeout enable dns server!");
		exit(0);
	}

	ptr->dnsserver->timeout = atol(str);
}

void Parse_DNSServer(zroxy_t *ptr,char *str)
{
	if(!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)malloc(sizeof(dnshost_t));
	}

	ptr->dnsserver->Stat = NULL;
	ptr->dnsserver->Local.port	= 53;
	ptr->dnsserver->timeout		= 5;
	bzero(ptr->dnsserver->Local.ip,_MaxIPAddress_);
	strcpy(ptr->dnsserver->Local.ip,"127.0.0.1");


	char *endname = strchr(str,':');
	if(endname)
	{
		*endname++ = 0;
		strncpy(ptr->dnsserver->Local.ip,str,_MaxIPAddress_-1);
		ptr->dnsserver->Local.port = atol(endname);
	}
	else
	{
		strncpy(ptr->dnsserver->Local.ip,str,_MaxIPAddress_-1);
	}
}

void Parse_Snip(zroxy_t *ptr,char *str)
{
	while(*str==' ')
		str++;

	/*check dns config is exisit*/
	if(!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)malloc(sizeof(dnshost_t));
		ptr->dnsserver->Local.port = 53;
		bzero(ptr->dnsserver->Local.ip,_MaxIPAddress_);
		strcpy(ptr->dnsserver->Local.ip,"127.0.0.1");
	}

	uint8_t *sni_ip = ptr->dnsserver->sni_ip;
	
	int si[4];
	int p = sscanf(str,"%i.%i.%i.%i",&si[0],&si[1],&si[2],&si[3]);
	if(p==4)
	{
		sni_ip[0] = si[0];
		sni_ip[1] = si[1];
		sni_ip[2] = si[2];
		sni_ip[3] = si[3];
	}

}

void Parse_DnsUpstream(zroxy_t *ptr,char *str)
{
	/*check dns config is exisit*/
	if(!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)malloc(sizeof(dnshost_t));
		ptr->dnsserver->Local.port = 53;
		bzero(ptr->dnsserver->Local.ip,_MaxIPAddress_);
		strcpy(ptr->dnsserver->Local.ip,"127.0.0.1");
	}

	char *port = "53";
	char *endname = strchr(str,':');
	if(endname)
	{
		*endname++ =0;
	}
	else
	{
		endname = port;
	}

	ptr->dnsserver->Remote.port = atol(endname);
	strcpy(ptr->dnsserver->Remote.ip,str);
}

void Parse_Socks(zroxy_t *ptr,char *str)
{
	ptr->socks = (sockshost_t*)malloc(sizeof(sockshost_t));
	ptr->socks->port = 1080;
	
	char *Userpass = strchr(str,'@'); 
	/*we have user passWord*/
	if(Userpass)
	{
		*Userpass++ = 0;
		char *ipPort = Userpass;
		Userpass = str;

		char *endname = strchr(Userpass,':');
		if(endname)
		{
			*endname++ = 0;
			ptr->socks->user = strdup(Userpass);
			ptr->socks->pass = strdup(endname);
		}
		else
		{
			ptr->socks->user = strdup(Userpass);
		}


		endname = strchr(ipPort,':');
		if(endname)
		{
			*endname++ = 0;
			ptr->socks->host = strdup(ipPort);
			ptr->socks->port = atol(endname);
		}
		else
		{
			ptr->socks->host = strdup(ipPort);
		}
	}
	else
	{
		/*we don't have user password*/
		char *endname = strchr(str,':');
		if(endname)
		{
			*endname++ = 0;
			ptr->socks->host = strdup(str);
			ptr->socks->port = atol(endname);
		}
		else
		{
			ptr->socks->host = strdup(str);
		}
	}
}

void Parse_Ports(zroxy_t *ptr,char *str)
{
	void *perv = NULL;
	do{
		ptr->ports = (lport_t*)malloc(sizeof(lport_t));

		char *xptr = str;
		str = strchr(str,',');
		if(str)
		{
			*str++=0;
		}

		/*check for ip*/
		char *Iptr = strchr(xptr,':');
		if(Iptr)
		{
			*Iptr++=0;
			strcpy(ptr->ports->bindip,xptr);
			bool valid_ip = validate_ip(xptr);
			if(valid_ip==false)
			{
				log_error("[!] Error Not valid ip -> %s",ptr->ports->bindip);
				exit(0);
			}

			xptr = Iptr;
		}
		else
		{
			strcpy(ptr->ports->bindip,"0.0.0.0");
		}

		char *Pptr = strchr(xptr,'@');
		if(Pptr)
		{
			*Pptr++=0;
			ptr->ports->local_port = atol(xptr);
			ptr->ports->remote_port = atol(Pptr);
		}
		else
		{
			ptr->ports->local_port = atol(xptr);
			ptr->ports->remote_port = ptr->ports->local_port;
		}

		ptr->ports->next = perv;
		perv = ptr->ports;

	}while( str!=NULL );
}

void Free_PortList(zroxy_t *ptr)
{
	lport_t *p=ptr->ports;
	while(p)
	{
		lport_t *next = p->next;
		free(p);
		p=next;
	}
}

void Parse_DnsSocks(zroxy_t *ptr,char *str)
{
	ptr->dnsserver->Socks = (sockshost_t*)malloc(sizeof(sockshost_t));
	sockshost_t *socks = ptr->dnsserver->Socks;

	socks->port = 1080;
	
	char *Userpass = strchr(str,'@'); 
	/*we have user passWord*/
	if(Userpass)
	{
		*Userpass++ = 0;
		char *ipPort = Userpass;
		Userpass = str;

		char *endname = strchr(Userpass,':');
		if(endname)
		{
			*endname++ = 0;
			socks->user = strdup(Userpass);
			socks->pass = strdup(endname);
		}
		else
		{
			socks->user = strdup(Userpass);
		}


		endname = strchr(ipPort,':');
		if(endname)
		{
			*endname++ = 0;
			socks->host = strdup(ipPort);
			socks->port = atol(endname);
		}
		else
		{
			socks->host = strdup(ipPort);
		}
	}
	else
	{
		/*we don't have user password*/
		char *endname = strchr(str,':');
		if(endname)
		{
			*endname++ = 0;
			socks->host = strdup(str);
			socks->port = atol(endname);
		}
		else
		{
			socks->host = strdup(str);
		}
	}
}
