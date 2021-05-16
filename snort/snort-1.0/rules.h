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

#ifndef __RULES_H__
#define __RULES_H__

/*  I N C L U D E S  **********************************************************/
#include "snort.h"
#include <string.h>
#include <ctype.h>


/*  D E F I N E S  ************************************************************/
#define RULE_LOG   0
#define RULE_PASS  1
#define RULE_ALERT 2

#define ANY_SRC_IP     0x01
#define ANY_DST_IP     0x02
#define ANY_SRC_PORT   0x04
#define ANY_DST_PORT   0x08
#define ANY_FLAGS      0x10

#define R_FIN          0x01
#define R_SYN          0x02
#define R_RST          0x04
#define R_PSH          0x08
#define R_ACK          0x10
#define R_URG          0x20

/*  D A T A  S T R U C T U R E S  *********************************************/
typedef struct _Rule
{
   int rule_num;        /* for debug purposes */
   int type;            /* alert, log, or pass */
   u_long sip;          /* src IP */
   u_long smask;        /* src netmask */
   u_long dip;          /* dest IP */
   u_long dmask;        /* dest netmask */
   int not_sp_flag;     /* not implemented yet... */
   u_short hsp;         /* hi src port */
   u_short lsp;         /* lo src port */
   int not_dp_flag;     /* not implemented yet... */
   u_short hdp;         /* hi dest port */
   u_short ldp;         /* lo dest port */
   u_char tcp_flags;    /* self explainatory */
   int check_tcp_flags; /* program flag */
   int proto;           /* protocol */
   int pattern_match_flag; /* program flag */
   int icmp_type;       /* ICMP type */
   int use_icmp_type;
   int icmp_code;       /* ICMP code */
   int use_icmp_code;
   int ttl;             /* TTL value */ 
   u_char flags;        /* control flags */
   char *message;       /* alert message */
   u_int pattern_size;  /* size of app layer pattern */
   char *pattern_buf;   /* app layer pattern to match on */
   struct _Rule *next;  /* ptr to the next rule */
} Rule;
   

/*  P R O T O T Y P E S  ******************************************************/
void ParseRulesFile(char *);
void ParseRule(char *);
void CreateRuleNode(int);
int RuleType(char *);
int WhichProto(char *);
int  ParseIP(char *, u_long *, u_long *);
int ParsePort(char *, u_short *,  u_short *, char *, int *);
void ApplyRules();
int CheckRules(Rule *);
void LogPkt();
void AlertPkt();
void DumpRuleList(Rule *);
void ParsePattern(char *);
void ParseFlags(char *);
int ConvPort(char *, char *);
void ParseRuleOptions(char *);
void ParseIcode(char *);
void ParseItype(char *);
void ParseMessage(char *);
void ParseFlags(char *);


#endif /* __RULES_H__ */
