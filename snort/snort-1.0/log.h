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

#ifndef __LOG_H__
#define __LOG_H__


/*  I N C L U D E S  **********************************************************/
#include "snort.h"


#define FRAME_SIZE        66
#define C_OFFSET          49

#define DUMP              1
#define BOGUS             2
#define NON_IP            3

/*  D A T A  S T R U C T U R E S  *********************************************/
typedef struct _PrintIP
{
   u_char timestamp[64];   /* packet timestamp */
   u_char eth_src[6];
   u_char eth_dst[6];
   u_short eth_type;
   u_int eth_len;
   u_char saddr[16];       /* src ip addr */
   u_char daddr[16];       /* dst ip addr */
   u_short sport;          /* src port */
   u_short dport;          /* dst port */
   char sport_name[16];    /* src port name */
   char dport_name[16];    /* dst port name */
   u_long seq;             /* TCP sequence number */
   u_long ack;             /* TCP acknowledge number */
   u_char flags;           /* TCP flags */
   char proto[5];          /* datagram protocol */
   u_long win;             /* IP window size */
   u_char ttl;             /* IP time to live */
   u_char tos;             /* IP type of service */
   u_char ip_df;           /* IP don't fragment flag */
   u_char ip_mf;           /* IP more fragments flag */
   u_short frag_id;        /* IP fragment ID field */
   u_short frag_off;       /* IP fragment offset field */
   u_short udp_len;        /* UDP app layer length field */
   u_short icmp_type;
   u_short icmp_code;
   u_char icmp_str[64];    /* ICMP type/code string */
   u_short icmp_id;        /* ICMP (ping) id number */
   u_short icmp_seqno;     /* ICMP (ping) sequence number */
   u_int dsize;            /* packet data size */
   int IPO_flag;           /* IP Options are present */
   u_char IPO_Str[160];     /* IP Options string */
   int TO_flag;            /* TCP Options flag */
   char TO_Str[160];    /* TCP option string */
   char *data;             /* ptr to the packet data (app layer) */
} PrintIP;


/*  P R O T O T Y P E S  ******************************************************/
int OpenLogFile(int);
void OpenAlertFile();
void PrintIPPkt(FILE *, int);
void PrintNetData(FILE *, char *, const int);
void PrintFragHeader(FILE *);
void ClearDumpBuf();
void AlertPkt();
void LogPkt();
void PrintEthHeader(FILE *);
void PrintIPHeader(FILE *);
void PrintTCPHeader(FILE *);
void PrintICMPHeader(FILE *);
void PrintUDPHeader(FILE *);


#endif /* __LOG_H__ */
