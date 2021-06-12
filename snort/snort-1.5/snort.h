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
#include <sys/un.h>
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
#include "plugbase.h"

/*  D E F I N E S  ************************************************************/
#define STD_BUF  256

#define RF_ANY_SIP    0x01
#define RF_ANY_DIP    0x02
#define RF_ANY_SP     0x04
#define RF_ANY_DP     0x10
#define RF_ANY_FLAGS  0x20

#define DEFAULT_LOG_DIR   "/var/log/snort"
#define DEFAULT_DAEMON_ALERT_FILE  "/var/log/snort.alert"
#define UNSOCK_FILE       "/dev/snort_alert"

#define ALERT_FULL     0x01
#define ALERT_FAST     0x02
#define ALERT_NONE     0x03
#define ALERT_UNSOCK   0x04

/*  D A T A  S T R U C T U R E S  *********************************************/
/* struct to contain the program variables and command line args */
typedef struct _progvars
{
   int session_flag;
   int data_flag;
   int verbose_flag;
   int showarp_flag;
   int showipx_flag;
   int readmode_flag;
   int logbin_flag;
   int log_flag;
   int nolog_flag;
   int showeth_flag;
   int syslog_flag;
   int promisc_flag;
   int rules_order_flag;
   int smbmsg_flag;
   int track_flag;
   int daemon_flag;
   int pkt_cnt;
   u_long homenet;
   u_long netmask;
   int use_rules;
   int alert_mode;
   char config_file[STD_BUF];
   char log_dir[STD_BUF];
   char readfile[STD_BUF];
   char smbmsg_dir[STD_BUF];
   char *interface;
   char *pcap_cmd;
} PV;

/* struct to collect packet statistics */
typedef struct _PacketCount
{
   u_long other;
   u_long tcp;
   u_long udp;
   u_long icmp;
   u_long arp;
   u_long ipx;
} PacketCount;

/*  G L O B A L S  ************************************************************/
PV pv;                 /* program vars (command line args) */
int datalink;          /* the datalink value */
char *progname;        /* name of the program (from argv[0]) */
char *pcap_cmd;        /* the BPF command string */
char *pktidx;          /* index ptr for the current packet */
pcap_t *pd;            /* the packet descriptor */
pcap_handler grinder;  /* ptr to the packet processor */
FILE *log_ptr;         /* log file ptr */
FILE *alert;           /* alert file ptr */
FILE *binlog_ptr;      /* binary log file ptr */
FILE *session;         /* session file ptr */
int log_session;       /* log session flag */
int flow;              /* flow var (probably obsolete) */
int thiszone;          /* time zone info */
PacketCount pc;        /* packet count information */
u_long netmasks[33];   /* precalculated netmask array */
struct pcap_pkthdr *g_pkthdr; /* packet header ptr */
u_char *g_pkt;         /* ptr to the packet data */
u_long g_caplen;       /* length of the current packet */
char protocol_names[18][6];
u_int snaplen;
int alertsd;           /* socket descriptor for unix-socket logging */
struct sockaddr_un alertaddr; /* where we send all alert packets */


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
float CalcPct(float, float);
void ReadPacketsFromFile();
void GenHomenet(char *);
void InitNetmasks();
void InitBinFrag();
void GoDaemon();
void SanityChecks();
char *read_infile(char *);
void InitProtoNames();

#endif  /* __SNORT_H__ */
