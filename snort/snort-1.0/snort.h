/*
** Copyright (C) 1998,1999 Martin Roesch <roesch@clark.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __SNORT_H__
#define __SNORT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*  I N C L U D E S  **********************************************************/
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <math.h>
#include <ctype.h>
#include <pcap-namedb.h>
#include <netdb.h>
#include <syslog.h>
#include "decode.h"
#include "rules.h"
#include "log.h"
#include "mstring.h"


/*  D E F I N E S  ************************************************************/
/*
#ifdef SOLARIS
#define DEFAULT_INTF	"hme0"
#endif

#ifdef LINUX
#define DEFAULT_INTF	"eth0"
#endif

#ifdef FREEBSD
#define DEFAULT_INTF    "xl0"
#endif
*/
#define STD_BUF  256

#define RIGHT    1
#define LEFT     0


#define RF_ANY_SIP    0x01
#define RF_ANY_DIP    0x02
#define RF_ANY_SP     0x04
#define RF_ANY_DP     0x10
#define RF_ANY_FLAGS  0x20



/*  D A T A  S T R U C T U R E S  *********************************************/
typedef struct progvars
{
   int data_flag;
   int verbose_flag;
   int showarp_flag;
   int log_flag;
   int pkt_cnt;
   u_long homenet;
   u_long netmask;
   int use_rules;
   char config_file[STD_BUF];
   char log_dir[STD_BUF];
   int showeth_flag;
   int syslog_flag;
   int rules_order_flag;
   char *interface;
   char *pcap_cmd;
} PV;


typedef struct _NetData
{
   unsigned long sip;
   unsigned long dip;
   unsigned short sp;
   unsigned short dp;
   unsigned int proto;
   unsigned char tcp_flags;
} NetData;



/*  G L O B A L S  ************************************************************/
PV pv;
int datalink;
char *progname;
char *pcap_cmd;
char *pktidx;
pcap_t *pd;
pcap_handler grinder;
FILE *log_ptr;
FILE *alert;
int flow;
NetData net;
int thiszone;


/*  P R O T O T Y P E S  ******************************************************/
int ParseCmdLine(int, char**);
int OpenPcap(char *);
int DisplayBanner();
int SetPktProcessor();
void GetTime(char *);
int gmt2local(time_t);
void ts_print(register const struct timeval *, char *);
void CleanExit();
char *copy_argv(char **);
int strip(char *);
int ShowUsage(char *);


#endif  /* __SNORT_H__ */
