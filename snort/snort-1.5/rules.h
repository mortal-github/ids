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

/*  I N C L U D E S  **********************************************************/
#include "snort.h"

/*  D E F I N E S  ************************************************************/
#ifndef __RULES_H__
#define __RULES_H__


#ifdef SOLARIS
#define INADDR_NONE -1
#endif

#define RULE_LOG     0
#define RULE_PASS    1
#define RULE_ALERT   2
#define RULE_VAR     3
#define RULE_INCLUDE 4
#define RULE_PREPROCESS 5

#define EXCEPT_SRC_IP  0x01
#define EXCEPT_DST_IP  0x02
#define ANY_SRC_PORT   0x04
#define ANY_DST_PORT   0x08
#define ANY_FLAGS      0x10
#define EXCEPT_SRC_PORT 0x20
#define EXCEPT_DST_PORT 0x40
#define BIDIRECTIONAL   0x80

#define R_FIN          0x01
#define R_SYN          0x02
#define R_RST          0x04
#define R_PSH          0x08
#define R_ACK          0x10
#define R_URG          0x20
#define R_RES2         0x40
#define R_RES1         0x80


#define MODE_EXIT_ON_MATCH   0
#define MODE_FULL_SEARCH     1

#define CHECK_SRC            0x01
#define CHECK_DST            0x02
#define INVERSE              0x04

#define SESSION_PRINTABLE    1
#define SESSION_ALL          2

#define MODE_EXIT_ON_MATCH   0
#define MODE_FULL_SEARCH     1

#define SRC                  0
#define DST                  1

/*  D A T A  S T R U C T U R E S  *********************************************/
/* I'm forward declaring the rules structures so that the function
   ponter lists can reference them nternally */
struct _OptTreeNode;      /* forward declaration of OTN data struct */
struct _RuleTreeNode;     /* forward declaration of RTN data struct */

/* function pointer list for rule head nodes */
typedef struct _RuleFpList
{
   /* rule check function pointer */
   int (*RuleHeadFunc)(Packet *, struct _RuleTreeNode *, struct _RuleFpList *);

   /* pointer to the next rule function node */
   struct _RuleFpList *next;

} RuleFpList;

/* same as the rule header FP list */
typedef struct _OptFpList
{
   int (*OptTestFunc)(Packet *, struct _OptTreeNode *, struct _OptFpList *);

   struct _OptFpList *next;

} OptFpList;


typedef struct _OptTreeNode
{
   /* plugin/detection functions go here */
   OptFpList *opt_func;

   /* the ds_list is absolutely essential for the plugin system to work,
      it allows the plugin authors to associate "dynamic" data structures
      with the rule system, letting them link anything they can come up 
      with to the rules list */
   void *ds_list[512];   /* list of plugin data struct pointers */

   int chain_node_number;

   int type;            /* alert, log, or pass */
   int proto;           /* protocol, added for integrity checks 
                           during rule parsing */

   int session_flag;    /* record session data */

   char *logto;         /* log file in which to write packets which 
                           match this rule*/

   char *message;       /* alert message */

   struct _OptTreeNode *next;

} OptTreeNode;



typedef struct _RuleTreeNode
{
   RuleFpList *rule_func;

   int head_node_number;

   int type;

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

   u_char flags;        /* control flags */

   struct _RuleTreeNode *right;

   OptTreeNode *down;   /* list of rule options to associate with this
                           rule node */

} RuleTreeNode;



typedef struct _ListHead
{
   RuleTreeNode *TcpList;
   RuleTreeNode *UdpList;
   RuleTreeNode *IcmpList;
} ListHead; 


struct VarEntry
{
   char *name;
   char *value;
   struct VarEntry *prev;
   struct VarEntry *next;
};


/*  P R O T O T Y P E S  ******************************************************/

/* rule setup funcs */
void ParseRulesFile(char *, int);
void ParseRule(char *, int);
int RuleType(char *);
void ProcessHeadNode(RuleTreeNode *, ListHead *, int);
void ParsePreprocessor(char *);
int WhichProto(char *);
void ParseRuleOptions(char *, int, int);
int ParseIP(char *, u_long *, u_long *);
int ParsePort(char *, u_short *,  u_short *, char *, int *);
void ParseMessage(char *);
void ParseLogto(char *);
void ParseSession(char *);
int ConvPort(char *, char *);
int TestHeader(RuleTreeNode *, RuleTreeNode *);
void XferHeader(RuleTreeNode *, RuleTreeNode *);
void DumpChain(RuleTreeNode *, char *);
struct VarEntry *VarAlloc();
void VarDefine(char *, char *);
void VarDelete(char *);
char *VarGet(char *);
char *ExpandVars(char *);
void IntegrityCheck(RuleTreeNode *, char *);

/* detection/manipulation funcs */
void Preprocess(Packet *);
void Detect(Packet *);
int EvalPacket(ListHead *, int, Packet * );
int EvalHeader(RuleTreeNode *, Packet *);
int EvalOpts(OptTreeNode *, Packet *);
int CheckAddrPort(u_long, u_long, u_short, u_short, Packet *, char, int);

void AddrToFunc(RuleTreeNode *, u_long, u_long, int, int);
void PortToFunc(RuleTreeNode *, int, int, int);
void SetupRTNFuncList(RuleTreeNode *);
void AddOptFuncToList(int (*func)(Packet *,struct _OptTreeNode*,struct _OptFpList*), OptTreeNode *);
void AddFuncToPreprocList(void (*func)(Packet *));

/* detection modules */
int CheckBidirectional(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcIPEqual(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstIPEqual(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcIPNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstIPNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcPortEqual(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstPortEqual(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckSrcPortNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *);
int CheckDstPortNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *);

int RuleListEnd(Packet *, struct _RuleTreeNode *, RuleFpList *);
int OptListEnd(Packet *, struct _OptTreeNode *, OptFpList *);
#endif /* __RULES_H__ */
