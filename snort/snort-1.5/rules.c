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

#include "rules.h"

ListHead Alert;      /* Alert Block Header */
ListHead Log;        /* Log Block Header */
ListHead Pass;       /* Pass Block Header */

RuleTreeNode *rtn_tmp;  /* temp data holder */
OptTreeNode *otn_tmp;   /* OptTreeNode temp ptr */

struct VarEntry	*VarHead = NULL;

char *file_name;    /* current rules file being processed */
int file_line;      /* current line being processed in the rules file */
int rule_count;     /* number of rules generated */
int head_count;     /* number of header blocks (chain heads?) */
int opt_count;      /* number of chains */
int do_detect;


extern KeywordXlateList *KeywordList;
extern PreprocessKeywordList *PreprocessKeywords;
extern PreprocessFuncNode *PreprocessList;

#ifdef BENCHMARK
int check_count;    /* number of tests for a given rule to determine a match */
int cmpcount;       /* compare counter */
#endif


/****************************************************************************
 *
 * Function: ParseRulesFile(char *, int)
 *
 * Purpose:  Read the rules file a line at a time and send each rule to
 *           the rule parser
 *
 * Arguments: file => rules file filename
 *            inclevel => nr of stacked "include"s
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRulesFile(char *file, int inclevel)
{
   FILE *thefp;       /* file pointer for the rules file */
   char buf[STD_BUF]; /* file read buffer */
   char *stored_file_name = file_name;
   int  stored_file_line = file_line;

#ifdef DEBUG
   printf("Opening rules file: %s\n", file);
#endif
   if(inclevel == 0)
   {
      printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++\n");
      printf("Initializing rule chains...\n");
      file_name = strdup(file);
   }

   /* open the rules file */
   if((thefp = fopen(file,"r")) == NULL)
   {
      printf("Unable to open rules file: %s\n", file);
      exit(1);
   }

   /* clear the line buffer */
   bzero(buf, STD_BUF);

   stored_file_line = file_line;
   stored_file_name = file_name;
   file_name = strdup(file);
   file_line = 0;

   /* loop thru each file line and send it to the rule parser */
   while((fgets(buf, STD_BUF, thefp)) != NULL)
   {
      /* inc the line counter so the error messages know which line to 
         bitch about */
      file_line++;

#ifdef DEBUG2
      printf("Got line %s (%d): %s", file_name, file_line, buf);
#endif
      /* if it's not a comment or a <CR>, send it to the parser */
      if((buf[0] != '#') && (buf[0] != 0x0a) && (buf[0] != ';'))
      {
         ParseRule(buf, inclevel);
      }

      bzero(buf, STD_BUF);
   }

   if(file_name)
      free(file_name);
   file_name = stored_file_name;
   file_line = stored_file_line;

   if(inclevel == 0)
   {
      printf("%d Snort rules read...\n", rule_count);
      printf("%d Option Chains linked into %d Chain Headers\n", opt_count, head_count);
      printf("+++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
   }

   fclose(thefp);

   if(inclevel == 0)
   {
#ifdef DEBUG
      DumpChain(Alert.TcpList, "Alert TCP Chains");
      DumpChain(Alert.UdpList, "Alert UDP Chains");
      DumpChain(Alert.IcmpList, "Alert ICMP Chains");


      DumpChain(Log.TcpList, "Log TCP Chains");
      DumpChain(Log.UdpList, "Log UDP Chains");
      DumpChain(Log.IcmpList, "Log ICMP Chains");


      DumpChain(Pass.TcpList, "Pass TCP Chains");
      DumpChain(Pass.UdpList, "Pass UDP Chains");
      DumpChain(Pass.IcmpList, "Pass ICMP Chains");
#endif
  
      printf("Performing Rule List Integrity Tests...\n");
      printf("---------------------------------------\n");
      IntegrityCheck(Alert.TcpList,"Alert TCP Chains" );
      IntegrityCheck(Alert.UdpList, "Alert UDP Chains");
      IntegrityCheck(Alert.IcmpList, "Alert ICMP Chains");

      IntegrityCheck(Log.TcpList, "Log TCP Chains");
      IntegrityCheck(Log.UdpList, "Log UDP Chains");
      IntegrityCheck(Log.IcmpList, "Log ICMP Chains");

      IntegrityCheck(Pass.TcpList, "Pass TCP Chains");
      IntegrityCheck(Pass.UdpList, "Pass UDP Chains");
      IntegrityCheck(Pass.IcmpList, "Pass ICMP Chains");
      printf("---------------------------------------\n\n");
   }

   return;
}



/****************************************************************************
 *
 * Function: ParseRule(char *, int)
 *
 * Purpose:  Process an individual rule and add it to the rule list
 *
 * Arguments: rule => rule string
 *            inclevel => nr of stacked "include"s
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRule(char *prule, int inclevel)
{
   char **toks;          /* dbl ptr for mSplit call, holds rule tokens */
   int num_toks;         /* holds number of tokens found by mSplit */
   int rule_type;        /* rule type enumeration variable */
   char rule[1024];
   int protocol;
   RuleTreeNode proto_node;

   /* clean house */
   bzero(&proto_node, sizeof(RuleTreeNode));

   /* chop off the <CR/LF> from the string */
   strip(prule);

   /* expand all variables */
   strcpy(rule, ExpandVars(prule));

   /* break out the tokens from the rule string */
   toks = mSplit(rule, " ", 10, &num_toks,0);

#ifdef DEBUG
      printf("[*] Rule start\n");
#endif

   /* figure out what we're looking at */
   rule_type = RuleType(toks[0]);

   proto_node.type = rule_type;

#ifdef DEBUG
   printf("Rule type: ");
#endif

   /* handle non-rule entries */
   switch(rule_type)
   {
      case RULE_PASS:
#ifdef DEBUG
         printf("Pass\n");
#endif
         break;

      case RULE_LOG:
#ifdef DEBUG
         printf("Log\n");
#endif
         break;

      case RULE_ALERT:
#ifdef DEBUG
         printf("Alert\n");
#endif
         break;

      case RULE_INCLUDE:
#ifdef DEBUG
         printf("Include\n");
#endif
         ParseRulesFile(toks[1], inclevel + 1);
         return;

      case RULE_VAR:
#ifdef DEBUG
         printf("Variable\n");
#endif
         VarDefine(toks[1], toks[2]);
         return;

      case RULE_PREPROCESS:
#ifdef DEBUG
         printf("Preprocessor\n");
#endif
         ParsePreprocessor(rule);
         return;
   }

   /* set the rule protocol */
   protocol = WhichProto(toks[1]);

   /* Process the IP address and CIDR netmask */
   /* changed version 1.2.1 */
   /* "any" IP's are now set to addr 0, netmask 0, and the normal rules are 
      applied instead of checking the flag */
   /* if we see a "!<ip number>" we need to set a flag so that we can properly 
      deal with it when we are processing packets */
   if(*toks[2]=='!')  /* we found a negated address*/
   {
      proto_node.flags |= EXCEPT_SRC_IP;
      ParseIP(&toks[2][1], (u_long *) &proto_node.sip,
              (u_long *) &proto_node.smask);
   }
   else
   {
      ParseIP(toks[2], (u_long *) &proto_node.sip,
              (u_long *) &proto_node.smask);
   }

   /* do the same for the port */
   if(ParsePort(toks[3], (u_short *) &proto_node.hsp, 
               (u_short *) &proto_node.lsp, toks[1], 
               (int *) &proto_node.not_sp_flag))
   {
      proto_node.flags |= ANY_SRC_PORT;
   }

   if(proto_node.not_sp_flag)
      proto_node.flags |= EXCEPT_SRC_PORT;

   /* New in version 1.3: support for bidirectional rules */
   /* this checks the rule "direction" token and sets the bidirectional
      flag if the token = '<>' */
   if(!strncmp("<>", toks[4], 2))
   {
#ifdef DEBUG
      printf("Bidirectional rule!\n");
#endif
      proto_node.flags |= BIDIRECTIONAL;
   }

   /* changed version 1.2.1 */
   /* "any" IP's are now set to addr 0, netmask 0, and the normal rules are
       applied instead of checking the flag */
   /* if we see a "!<ip number>" we need to set a flag so that we can properly 
      deal with it when we are processing packets */
   if(*toks[5]=='!')  /*we found a negated address*/
   {
#ifdef DEBUG
      printf("setting exception flag for dest IP\n");
#endif
      proto_node.flags |= EXCEPT_DST_IP;
      ParseIP(&toks[5][1], (u_long *) &proto_node.dip,
              (u_long *) &proto_node.dmask);
   }
   else
      ParseIP(toks[5], (u_long *) &proto_node.dip,
              (u_long *) &proto_node.dmask);

   if(ParsePort(toks[6], (u_short *) &proto_node.hdp, 
                (u_short *) &proto_node.ldp, toks[1], 
                (int *) &proto_node.not_dp_flag))
   {
      proto_node.flags |= ANY_DST_PORT;
   }
      
   if(proto_node.not_dp_flag)
      proto_node.flags |= EXCEPT_DST_PORT;

#ifdef DEBUG
   printf("proto_node.flags = 0x%X\n", proto_node.flags);
#endif

   switch(rule_type)
   {
      case RULE_ALERT:
         ProcessHeadNode(&proto_node, &Alert, protocol); 
         break;

      case RULE_LOG:
         ProcessHeadNode(&proto_node, &Log, protocol); 
         break;

      case RULE_PASS:
         ProcessHeadNode(&proto_node, &Pass, protocol); 
         break;
   }

   rule_count++;
   ParseRuleOptions(rule, rule_type, protocol);

   free(toks);

   return;
}


/****************************************************************************
 *
 * Function: ProcessHeadNode(RuleTreeNode *, ListHead *, int)
 *
 * Purpose:  Process the header block info and add to the block list if 
 *           necessary
 *
 * Arguments: test_node => data generated by the rules parsers
 *            list => List Block Header refernece
 *            protocol => ip protocol
 *
 * Returns: void function
 *
 ***************************************************************************/
void ProcessHeadNode(RuleTreeNode *test_node, ListHead *list, int protocol)
{
   int match = 0;
   RuleTreeNode *rtn_idx;
   int count = 0;

   /* select the proper protocol list to attach the current rule to */
   switch(protocol)
   {
      case IPPROTO_TCP:
            rtn_idx =  list->TcpList; 
            break;

      case IPPROTO_UDP:
            rtn_idx =  list->UdpList; 
            break;

      case IPPROTO_ICMP:
            rtn_idx =  list->IcmpList; 
            break;

      default: rtn_idx = NULL;
             break;
   }

   /* if the list head is NULL (empty), make a new one and attach 
      the ListHead to it */
   if(rtn_idx == NULL)
   {
      head_count++;

      switch(protocol)
      {
      case IPPROTO_TCP:
            list->TcpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), sizeof(char)); 
            rtn_tmp = list->TcpList;
            break;

      case IPPROTO_UDP:
            list->UdpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), sizeof(char)); 
            rtn_tmp = list->UdpList;
            break;

      case IPPROTO_ICMP:
            list->IcmpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), sizeof(char)); 
            rtn_tmp = list->IcmpList;
            break;
      }

      /* copy the prototype header data into the new node */
      XferHeader(test_node, rtn_tmp);

      rtn_tmp->head_node_number = head_count; 

      /* null out the down (options) pointer */
      rtn_tmp->down = NULL;

      /* add the function list to the new rule */
      SetupRTNFuncList(rtn_tmp);

      return;
   }

   /* see if this prototype node matches any of the existing header nodes */
   match = TestHeader(rtn_idx,test_node);

   while((rtn_idx->right != NULL) && !match)
   {
      count++;
      match = TestHeader(rtn_idx,test_node);

      if(!match)
         rtn_idx = rtn_idx->right;
      else
         break;
   }

   /* have to check this twice since my loop above exits early, which sucks 
      but it's not performance critical */
   match = TestHeader(rtn_idx,test_node);

   /* if it doesn't match any of the existing nodes, make a new node and stick
      it at the end of the list */
   if(!match)
   {
#ifdef DEBUG
      printf("Building New Chain head node\n");
#endif

      head_count++;

      /* build a new node */
      rtn_idx->right = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), sizeof(char));
   
      /* set the global ptr so we can play with this from anywhere */
      rtn_tmp = rtn_idx->right;

      /* uh oh */
      if(rtn_tmp == NULL)
      {
         fprintf(stderr, "ERROR: Unable to allocate Rule Head Node!!\n");
         exit(1);
      }

      /* copy the prototype header info into the new header block */
      XferHeader(test_node, rtn_tmp);

      rtn_tmp->head_node_number = head_count; 
      rtn_tmp->down = NULL;

      /* initialize the function list for the new RTN */
      SetupRTNFuncList(rtn_tmp);
#ifdef DEBUG
      printf("New Chain head flags = 0x%X\n", rtn_tmp->flags); 
#endif
   }
   else
   {
      rtn_tmp = rtn_idx;
#ifdef DEBUG
      printf("Chain head %d  flags = 0x%X\n", count, rtn_tmp->flags); 
#endif

#ifdef DEBUG
   printf("Adding options to chain head %d\n", count);
#endif
   }
}


/****************************************************************************
 *
 * Function: AddRuleFuncToList(int (*func)(), RuleTreeNode *)
 *
 * Purpose:  Adds RuleTreeNode associated detection functions to the
 *          current rule's function list
 *
 * Arguments: *func => function pointer to the detection function
 *            rtn   => pointer to the current rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void AddRuleFuncToList(int (*func)(Packet *,struct _RuleTreeNode*,struct _RuleFpList*), RuleTreeNode *rtn)
{
   RuleFpList *idx;

#ifdef DEBUG
   printf("Adding new rule to list\n");
#endif

   idx = rtn->rule_func;

   if(idx == NULL)
   {
      rtn->rule_func = (RuleFpList *) calloc(sizeof(RuleFpList), sizeof(char));

      rtn->rule_func->RuleHeadFunc = func; 
   }
   else
   {
      while(idx->next != NULL)
         idx = idx->next;

      idx->next = (RuleFpList *) calloc(sizeof(RuleFpList), sizeof(char));

      idx = idx->next;
      idx->RuleHeadFunc = func;
   }
}

   
/****************************************************************************
 *
 * Function: SetupRTNFuncList(RuleTreeNode *)
 *
 * Purpose: Configures the function list for the rule header detection 
 *          functions (addrs and ports)
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *
 * Returns: void function
 *
 ***************************************************************************/
void SetupRTNFuncList(RuleTreeNode *rtn)
{
#ifdef DEBUG
   printf("Initializing RTN function list!\n");
   printf("Functions: ");
#endif
 
   if(rtn->flags & BIDIRECTIONAL)
   {
#ifdef DEBUG
      printf("CheckBidirectional->\n");
#endif
      AddRuleFuncToList(CheckBidirectional, rtn);
   }
   else
   {
      /* link in the proper IP address detection function */
      /* the in-line "if" determines whether or not the negation operator has
         been set for this rule and tells the AddrToFunc call which function
         it should be linking in */
      AddrToFunc(rtn, rtn->sip, rtn->smask, (rtn->flags & EXCEPT_SRC_IP ? 1 : 0), SRC);

      /* last verse, same as the first (but for dest IP) ;) */
      AddrToFunc(rtn, rtn->dip, rtn->dmask, (rtn->flags & EXCEPT_DST_IP ? 1 : 0), DST);
             
      /* Attach the proper port checking function to the function list */
      /* the in-line "if's" check to see if the "any" or "not" flags have been
         set so the PortToFunc call can determine which port testing function
         to attach to the list */
      PortToFunc(rtn, (rtn->flags & ANY_SRC_PORT ? 1 : 0), 
                 (rtn->flags & EXCEPT_SRC_PORT ? 1: 0), SRC);   

      /* as above */
      PortToFunc(rtn, (rtn->flags & ANY_DST_PORT ? 1 : 0), 
                 (rtn->flags & EXCEPT_DST_PORT ? 1: 0), DST);   
   }

#ifdef DEBUG
   printf("RuleListEnd\n");
#endif
 
   /* tack the end (success) function to the list */
   AddRuleFuncToList(RuleListEnd, rtn);
}



void AddrToFunc(RuleTreeNode *rtn, u_long ip, u_long mask, int exception_flag, int mode)
{
   /* if IP and mask are both 0, this is a "any" IP and we don't need to 
      check it */
   if((ip == 0) && (mask == 0))
      return;    

   /* if the exception flag is up, test with the exception function */
   if(exception_flag) 
   {
      switch(mode)
      {
         case SRC:
#ifdef DEBUG
            printf("CheckSrcIPNotEq -> ");
#endif
            AddRuleFuncToList(CheckSrcIPNotEq, rtn);
            break;

         case DST:
#ifdef DEBUG
            printf("CheckDstIPNotEq -> ");
#endif
            AddRuleFuncToList(CheckDstIPNotEq, rtn);
            break;
      }

      return;
   }

   switch(mode)
   {
      case SRC:
#ifdef DEBUG
         printf("CheckSrcIPEqual -> ");
#endif
         AddRuleFuncToList(CheckSrcIPEqual, rtn);
         break;

      case DST:
#ifdef DEBUG
         printf("CheckDstIPEqual -> ");
#endif
         AddRuleFuncToList(CheckDstIPEqual, rtn);
         break;
   }
}



void PortToFunc(RuleTreeNode *rtn, int any_flag, int except_flag, int mode)
{
   if(any_flag)
      return;

   if(except_flag)
   {
      switch(mode)
      {
         case SRC:
#ifdef DEBUG
            printf("CheckSrcPortNotEq -> ");
#endif
            AddRuleFuncToList(CheckSrcPortNotEq, rtn);
            break;

         case DST:
#ifdef DEBUG
            printf("CheckDstPortNotEq -> ");
#endif
            AddRuleFuncToList(CheckDstPortNotEq, rtn);
            break;
      }

      return;
   }

   switch(mode)
   {
      case SRC:
#ifdef DEBUG
         printf("CheckSrcPortEqual -> ");
#endif
         AddRuleFuncToList(CheckSrcPortEqual, rtn);
         break;

      case DST:
#ifdef DEBUG
         printf("CheckDstPortEqual -> ");
#endif
         AddRuleFuncToList(CheckDstPortEqual, rtn);
         break;
   }

   return;   
}




void AddOptFuncToList(int (*func)(Packet *,struct _OptTreeNode*,struct _OptFpList*), OptTreeNode *otn)
{
   OptFpList *idx;

#ifdef DEBUG
   printf("Adding new rule to list\n");
#endif

   idx = otn->opt_func;

   if(idx == NULL)
   {
      otn->opt_func = (OptFpList *) calloc(sizeof(OptFpList), sizeof(char));

      if(otn->opt_func == NULL)
      {
         fprintf(stderr, "ERROR => AddOptFuncToList new node calloc failed!\n");
         perror("AddOptFuncToList");
         exit(1);
      }

      otn->opt_func->OptTestFunc = func; 
   }
   else
   {
      while(idx->next != NULL)
         idx = idx->next;

      idx->next = (OptFpList *) calloc(sizeof(OptFpList), sizeof(char));

      if(idx->next == NULL)
      {
         fprintf(stderr, "ERROR => AddOptFuncToList new node calloc failed!\n");
         perror("AddOptFuncToList");
         exit(1);
      }

      idx = idx->next;
      idx->OptTestFunc = func;
   }
}



void ParsePreprocessor(char *rule)
{
   char **toks;
   char **pp_head;
   char *funcname;
   char *pp_args = NULL;
   int num_toks;
   int found = 0;
   PreprocessKeywordList *pl_idx;

   toks = mSplit(rule, ":", 2, &num_toks,'\\');

   if(num_toks >= 1)
   {
      pp_args = toks[1];
   }

   pp_head = mSplit(toks[0], " ", 2, &num_toks, '\\');

   funcname = pp_head[1];

   pl_idx = PreprocessKeywords;

   while(pl_idx != NULL)
   {
#ifdef DEBUG
      printf("comparing: \"%s\" => \"%s\"\n", funcname, pl_idx->entry.keyword);
#endif
      if(!strcasecmp(funcname, pl_idx->entry.keyword))
      {
         pl_idx->entry.func(pp_args);
         found = 1;
      }

      if(!found)
      {
         pl_idx = pl_idx->next;
      }
      else
         break;
   }
}



void AddFuncToPreprocList(void (*func)(Packet *))
{
   PreprocessFuncNode *idx;

   idx = PreprocessList;

   if(idx == NULL)
   {
      PreprocessList = (PreprocessFuncNode *) calloc(sizeof(PreprocessFuncNode), sizeof(char));

      PreprocessList->func = func;
   }
   else
   {
      while(idx->next != NULL)
         idx = idx->next;

      idx->next = (PreprocessFuncNode *) calloc(sizeof(PreprocessFuncNode), sizeof(char));

      idx = idx->next;
      idx->func = func;
   }

   return;
}


/****************************************************************************
 *
 * Function: ParseRuleOptions(char *, int)
 *
 * Purpose:  Process an individual rule's options and add it to the 
 *           appropriate rule chain
 *
 * Arguments: rule => rule string
 *            rule_type => enumerated rule type (alert, pass, log)
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRuleOptions(char *rule, int rule_type, int protocol)
{
   char **toks = NULL;
   char **opts;
   char *idx;
   char *aux;
   int num_toks;
   int i;
   int num_opts;
   int found = 0;
   OptTreeNode *otn_idx;
   KeywordXlateList *kw_idx;

   /* set the OTN to the beginning of the list */
   otn_idx = rtn_tmp->down;

   /* make a new one and stick it either at the end of the list or 
      hang it off the RTN pointer */
   if(otn_idx != NULL)
   {
      /* loop to the end of the list */
      while(otn_idx->next != NULL)
      {
         otn_idx = otn_idx->next;
      }

      /* setup the new node */
      otn_idx->next = (OptTreeNode *) calloc(sizeof(OptTreeNode), sizeof(char));

      /* set the global temp ptr */
      otn_tmp = otn_idx->next;

      if(otn_tmp == NULL)
      {
         perror("ERROR: Unable to alloc OTN!");
         exit(1);
      }

      otn_tmp->next = NULL;
      opt_count++;

   }
   else
   {
      /* first entry on the chain, make a new node and attach it */
      otn_idx = (OptTreeNode *) calloc(sizeof(OptTreeNode), sizeof(char));

      bzero(otn_idx, sizeof(OptTreeNode));

      otn_tmp = otn_idx;

      if(otn_tmp == NULL)
      {
         fprintf(stderr, "ERROR: Unable to alloc OTN!\n");
         exit(1);
      }

      otn_tmp->next = NULL;
      rtn_tmp->down = otn_tmp;
      opt_count++;
   }

   otn_tmp->chain_node_number = opt_count;
   otn_tmp->type = rule_type;

   /* find the start of the options block */
   idx = index(rule, '(');
   i = 0;

   if(idx != NULL)
   {
      idx++;
     
      /* find the end of the options block */
      aux = strrchr(idx,')');

      /* get rid of the trailing ")" */
      *aux = 0;


      /* seperate all the options out, the seperation token is a semicolon */
      /* NOTE: if you want to include a semicolon in the content of your rule,
         it must be preceeded with a '\' */
      toks = mSplit(idx, ";", 10, &num_toks,'\\');

#ifdef DEBUG
      printf("   Got %d tokens\n", num_toks);
#endif
      /* decrement the number of toks */
      num_toks--;

#ifdef DEBUG
      printf("Parsing options list: ");
#endif

      while(num_toks)
      {
#ifdef DEBUG
         printf("   option: %s\n", toks[i]);
#endif

         /* break out the option name from its data */
         opts = mSplit(toks[i], ":", 4, &num_opts,'\\');
         
#ifdef DEBUG
         printf("   option name: %s\n", opts[0]);
         printf("   option args: %s\n", opts[1]);
#endif
      
         /* advance to the beginning of the data (past the whitespace) */
         while(isspace((int)*opts[0])) opts[0]++;

         /* figure out which option tag we're looking at */
         if(!strcasecmp(opts[0], "msg"))
	 {
            ParseMessage(opts[1]);
         }
         else if(!strcasecmp(opts[0], "logto"))
         {
            ParseLogto(opts[1]); 
         }
         else if(!strcasecmp(opts[0], "session"))
         {
            otn_tmp->session_flag = 1;

            ParseSession(opts[1]);
         }
         else
         {

            kw_idx = KeywordList;
            found = 0;

            while(kw_idx != NULL)
            {
#ifdef DEBUG
               printf("comparing: \"%s\" => \"%s\"\n", opts[0], kw_idx->entry.keyword);
#endif
               if(!strcasecmp(opts[0], kw_idx->entry.keyword))
               {
                  kw_idx->entry.func(opts[1], otn_tmp, protocol);
                  found = 1;
#ifdef DEBUG
                  printf("%s->", kw_idx->entry.keyword);
#endif
               }

               if(!found)
               {
                  kw_idx = kw_idx->next;
               }
               else
                  break;
            }

            if(!found)
            {
               if(!strcasecmp(opts[0], "minfrag"))
               {
                  fprintf(stderr, "\nERROR: %s (%d) => Minfrag is no longer a rule option, it is a\npreprocessor (please remove it from your rules file).  See RULES.SAMPLE or\nsnort-lib for examples of using the new preprocessors!\n", file_name, file_line);
                  exit(1);
               }
               else
               {
                  fprintf(stderr, "\nERROR: %s (%d) => Unknown keyword \"%s\" in rule!\n", file_name, file_line, opts[0]);
                  exit(1);
               }
            }
         }

         free(opts);
	 --num_toks;
	 i++;
      }
#ifdef DEBUG
      printf("OptListEnd\n");
#endif

      AddOptFuncToList(OptListEnd, otn_tmp);
   }
   else
   {
#ifdef DEBUG
      printf("OptListEnd\n");
#endif

      AddOptFuncToList(OptListEnd, otn_tmp);
   }
      

   free(toks);
}


/****************************************************************************
 *
 * Function: RuleType(char *)
 *
 * Purpose:  Determine what type of rule is being processed and return its
 *           equivalent value
 *
 * Arguments: func => string containing the rule type
 *
 * Returns: The rule type designation
 *
 ***************************************************************************/
int RuleType(char *func)
{
   if(func == NULL)
   {
      printf("ERROR line %s (%d) => Unknown rule type\n", file_name, file_line);
      exit(1);
   }

   if(!strncasecmp(func, "log",3))
      return RULE_LOG;

   if(!strncasecmp(func, "alert",5))
      return RULE_ALERT;

   if(!strncasecmp(func, "pass",4))
      return RULE_PASS;

   if(!strncasecmp(func, "var",3))
      return RULE_VAR;

   if(!strncasecmp(func, "include",7))
      return RULE_INCLUDE;

   if(!strncasecmp(func, "preprocessor",12))
      return RULE_PREPROCESS;
   
   printf("ERROR line %s (%d) => Unknown rule type: %s\n", file_name, file_line, func);
   exit(1);
  
   return 0;
}

      

/****************************************************************************
 *
 * Function: WhichProto(char *)
 *
 * Purpose: Figure out which protocol the current rule is talking about
 *
 * Arguments: proto_str => the protocol string
 *
 * Returns: The integer value of the protocol
 *
 ***************************************************************************/
int WhichProto(char *proto_str)
{
   if(!strncasecmp(proto_str, "tcp", 3))
      return IPPROTO_TCP;

   if(!strncasecmp(proto_str, "udp", 3))
      return IPPROTO_UDP;

   if(!strncasecmp(proto_str, "icmp", 4))
      return IPPROTO_ICMP;

   /* if we've gotten here, we have a protocol string we din't recognize 
      and should exit */
   fprintf(stderr, "ERROR %s (%d) => Bad protocol: %s\n", file_name, file_line, proto_str);
   exit(1);
}


/****************************************************************************
 *
 * Function: ParseIP(char *, u_long *, u_long *)
 *
 * Purpose: Convert a supplied IP address to it's network order 32-bit long
           value.  Also convert the CIDR block notation into a real 
 *          netmask. 
 *
 * Arguments: addr => address string to convert
 *            ip_addr => storage point for the converted ip address
 *            netmask => storage point for the converted netmask
 *
 * Returns: 0 for normal addresses, 1 for an "any" address
 *
 ***************************************************************************/
int ParseIP(char *paddr, u_long *ip_addr, u_long *netmask)
{
   char **toks;      /* token dbl buffer */
   int num_toks;     /* number of tokens found by mSplit() */
   int nmask;        /* netmask temporary storage */
   char *addr;       /* string to parse, eventually a variable-contents */
   struct hostent *host_info;  /* various struct pointers for stuff */
   struct sockaddr_in sin;     /* addr struct */

   /* check for variable */
   if(! strncmp(paddr, "$", 1))
   {
      if((addr = VarGet(paddr + 1)) == NULL)
      {
         fprintf(stderr, "ERROR %s (%d) => Undefined variable %s\n", file_name, file_line, paddr);
         exit(1);
      }
   }
   else
      addr = paddr;

   /* check for wildcards */
   if(!strncasecmp(addr, "any", 3))
   {
      *ip_addr = 0;
      *netmask = 0;
      return 1;
   }
 
   /* break out the CIDR notation from the IP address */
   toks = mSplit(addr,"/",2,&num_toks,0);

   if(num_toks != 2)
   {
      fprintf(stderr, "ERROR %s (%d) => No netmask specified for IP address %s\n", file_name, file_line, addr);
      exit(1);
   }

   /* convert the CIDR notation into a real live netmask */
   nmask = atoi(toks[1]);

   if((nmask > 0)&&(nmask < 33))
   {
      *netmask = netmasks[nmask];
   }
   else
   {
      fprintf(stderr, "ERROR %s (%d) => Invalid CIDR block for IP addr %s\n", file_name, file_line, addr);
      exit(1);
   }

#ifndef WORDS_BIGENDIAN
   /* since PC's store things the "wrong" way, shuffle the bytes into
      the right order */
   *netmask = htonl(*netmask);
#endif

   /* convert names to IP addrs */
   if(isalpha((int)toks[0][0]))
   {
      /* get the hostname and fill in the host_info struct */
      if((host_info = gethostbyname(toks[0])))
      {
         bcopy(host_info->h_addr, (char *)&sin.sin_addr, host_info->h_length);
      }
      else if((sin.sin_addr.s_addr = inet_addr(toks[0])) == INADDR_NONE)
      {
         fprintf(stderr,"ERROR %s (%d) => Couldn't resolve hostname %s\n", 
                 file_name, file_line, toks[0]);
         exit(1);
      }

      *ip_addr = ((u_long)(sin.sin_addr.s_addr) & (*netmask));
      return 1;
   }

   /* convert the IP addr into its 32-bit value */
   if((*ip_addr = inet_addr(toks[0])) == -1)
   {
      fprintf(stderr, "ERROR %s (%d) => Rule IP addr (%s) didn't x-late, WTF?\n",
              file_name, file_line, toks[0]);
      exit(0);
   }
   else
   {
      /* set the final homenet address up */
      *ip_addr = ((u_long)(*ip_addr) & (*netmask));
   }

   free(toks);

   return 0;
}



/****************************************************************************
 *
 * Function: ParsePort(char *, u_short *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: prule_port => port rule string
 *            port => converted integer value of the port
 *
 * Returns: 0 for a normal port number, 1 for an "any" port
 *
 ***************************************************************************/
int ParsePort(char *prule_port, u_short *hi_port, u_short *lo_port, char *proto, int *not_flag)
{
   char **toks;         /* token dbl buffer */
   int num_toks;        /* number of tokens found by mSplit() */
   char *rule_port;     /* port string */

   *not_flag = 0;

   /* check for variable */
   if(! strncmp(prule_port, "$", 1))
   {
      if((rule_port = VarGet(prule_port + 1)) == NULL)
      {
         fprintf(stderr, "ERROR %s (%d) => Undefined variable %s\n", file_name, file_line, prule_port);
         exit(1);
      }
   }
   else
      rule_port = prule_port;

   /* check for wildcards */
   if(!strncasecmp(rule_port, "any", 3))
   {
      *hi_port = 0;
      *lo_port = 0;
      return 1;
   }

   if(rule_port[0] == '!')
   {
      *not_flag = 1;
      rule_port++;
   }

   if(rule_port[0] == ':')
   {
      *lo_port = 0;
   }

   toks = mSplit(rule_port, ":", 2, &num_toks,0);

   switch(num_toks)
   {
      case 1:
              *hi_port = ConvPort(toks[0], proto);

              if(rule_port[0] == ':')
              {
                 *lo_port = 0;
              }
              else
              {
                 *lo_port = *hi_port;

                 if(index(rule_port, ':') != NULL)
                 {
                    *hi_port = 65535;
                 }
              }

              return 0;

      case 2:
              *lo_port = ConvPort(toks[0], proto);

              if(toks[1][0] == 0)
                 *hi_port = 65535;
              else
                 *hi_port = ConvPort(toks[1], proto);

              return 0;

      default:
               fprintf(stderr, "ERROR %s (%d) => port conversion failed on \"%s\"\n",
                       file_name, file_line, rule_port);
               exit(1);
   }             

   return 0;
}


/****************************************************************************
 *       
 * Function: ConvPort(char *, char *)
 *    
 * Purpose:  Convert the port string over to an integer value
 * 
 * Arguments: port => port string
 *            proto => converted integer value of the port
 *
 * Returns:  the port number
 *
 ***************************************************************************/
int ConvPort(char *port, char *proto)
{
   int conv;  /* storage for the converted number */
   struct servent *service_info;

   /* convert a "word port" (http, ftp, imap, whatever) to its
      corresponding numeric port value */
   if(isalpha((int)port[0]) != 0)
   {
      service_info = getservbyname(port, proto);
 
      if(service_info != NULL)
      {
         conv = ntohs(service_info->s_port);
         return conv; 
      }
      else
      {
         fprintf(stderr, "ERROR %s (%d) => getservbyname() failed on \"%s\"\n",
                 file_name, file_line, port);
         exit(1);
      }
   }

   if(!isdigit((int)port[0]))
   {
      fprintf(stderr, "ERROR %s (%d) => Invalid port: %s\n", file_name, 
              file_line, port);
      exit(1);
   }  
   
   /* convert the value */
   conv = atoi(port);
   
   /* make sure it's in bounds */
   if((conv >= 0) && (conv < 65536))
   {
      return conv;
   }
   else
   {
      fprintf(stderr, "ERROR %s (%d) => bad port number: %s", file_name, 
              file_line, port);
      exit(1);
   }

   return 0;
}
 




/****************************************************************************
 *
 * Function: ParseMessage(char *)
 *
 * Purpose: Stuff the alert message onto the rule 
 *
 * Arguments: msg => the msg string 
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseMessage(char *msg)
{
   char *ptr;
   char *end;
   int size;

   /* figure out where the message starts */
   ptr = index(msg,'"');

   if(ptr == NULL)
   {
      ptr = msg;
   }
   else
      ptr++;
   
   end = index(ptr,'"');

   if(end != NULL)
      *end = 0;

   while(isspace((int) *ptr)) ptr++;

   /* find the end of the alert string */
   size = strlen(msg)+1;

   /* alloc space for the string and put it in the rule */
   if(size > 0)
   {
      otn_tmp->message = (char *)calloc((sizeof(char)*size), sizeof(char));
      strncpy(otn_tmp->message, ptr, size);
      otn_tmp->message[size-1] = 0;

#ifdef DEBUG
      printf("Rule message set to: %s\n", otn_tmp->message);
#endif

   }
   else 
   {
      fprintf(stderr, "ERROR %s (%d): bad alert message size %d\n", file_name, file_line, size);
   }
}



/****************************************************************************
 *
 * Function: ParseLogto(char *)
 *
 * Purpose: stuff the special log filename onto the proper rule option
 *
 * Arguments: filename => the file name
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseLogto(char *filename)
{
   char *sptr;
   char *eptr;

   /* grab everything between the starting " and the end one */
   sptr = index(filename, '"');
   eptr = strrchr(filename, '"');

   /* increment past the first quote */
   sptr++;

   /* zero out the second one */
   *eptr = 0;

   /* malloc up a nice shiny clean buffer */
   otn_tmp->logto = (char *) calloc(strlen(sptr) + 1, sizeof(char));

   bzero(otn_tmp->logto, strlen(sptr)+1);

   strncpy(otn_tmp->logto, sptr, strlen(sptr));
}




/****************************************************************************
 *
 * Function: ParseSession(char *)
 *
 * Purpose: Figure out how much of the session data we're collecting
 *
 * Arguments: type => string to indicate whether to just print the printable
 *                    chars or everything
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseSession(char *type)
{
   while(isspace((int)*type))
      type++;

   if(!strncasecmp(type, "printable", 9))
   {
      otn_tmp->session_flag = SESSION_PRINTABLE;
      return;
   }

   if(!strncasecmp(type, "all", 3))
   {
      otn_tmp->session_flag = SESSION_ALL;
      return;
   }

   fprintf(stderr, "ERROR %s (%d): invalid session modifier: %s\n", file_name, file_line, type);

   exit(1);
}



/****************************************************************************
 *
 * Function: XferHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Transfer the rule block header data from point A to point B
 *
 * Arguments: rule => the place to xfer from
 *            rtn => the place to xfer to
 *
 * Returns: void function
 *
 ***************************************************************************/
void XferHeader(RuleTreeNode *rule, RuleTreeNode *rtn)
{
   rtn->type = rule->type;
   rtn->sip = rule->sip;
   rtn->dip = rule->dip;
   rtn->smask = rule->smask;
   rtn->dmask = rule->dmask;
   rtn->hsp = rule->hsp;
   rtn->lsp = rule->lsp;
   rtn->hdp = rule->hdp;
   rtn->ldp = rule->ldp;
   rtn->flags = rule->flags;
}



/****************************************************************************
 *
 * Function: TestHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Check to see if the two header blocks are identical
 *
 * Arguments: rule => uh
 *            rtn  => uuuuhhhhh....
 *
 * Returns: 1 if they match, 0 if they don't
 *
 ***************************************************************************/
int TestHeader(RuleTreeNode *rule, RuleTreeNode *rtn)
{
   if(rtn->sip == rule->sip)
   {
      if(rtn->dip == rule->dip)
      {
         if(rtn->dmask == rule->dmask)
         {
            if(rtn->smask == rule->smask)
            {
               if(rtn->hsp == rule->hsp)
               {
                  if(rtn->lsp == rule->lsp)
                  {
                     if(rtn->hdp == rule->hdp)
                     {
                        if(rtn->ldp == rule->ldp)
                        {
                           if(rtn->flags == rule->flags)
                           {
                              return 1;
                           }
                        }
                     }
                  }
               }
            }
         }
      }
   }

   return 0;
}


/****************************************************************************
 *
 * Function: VarAlloc()
 *
 * Purpose: allocates memory for a variable
 *
 * Arguments: none
 *
 * Returns: pointer to new VarEntry
 *
 ***************************************************************************/
struct VarEntry *VarAlloc()
{
   struct VarEntry *new;

   if((new = (struct VarEntry *)calloc(sizeof(struct VarEntry), sizeof(char))) == NULL)
   {
      fprintf(stderr, "ERROR: cannot allocate memory for VarEntry.");
      exit(1);
   }

   new->name = NULL;
   new->value = NULL;
   new->prev = NULL;
   new->next = NULL;

   return(new);
}


/****************************************************************************
 *
 * Function: VarDefine(char *, char *)
 *
 * Purpose: define the contents of a variable
 *
 * Arguments: name => the name of the variable
 *            value => the contents of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
void VarDefine(char *name, char *value)
{
   struct VarEntry *p;
   int found = 0;


   if(! VarHead)
   {
      p = VarAlloc();
      p->name = strdup(name);
      p->value = strdup(value);
      p->prev = p;
      p->next = p;

      VarHead = p;

      return;
   }

   p = VarHead;

   do
   {
      if(strcasecmp(p->name, name) == 0)
      {
         found = 1;
         break;
      }

      p = p->next;
   } while(p != VarHead);

   if(found)
   {
      if(p->value)
         free(p->value);

      p->value = strdup(value);
   }
   else
   {
      p = VarAlloc();
      p->name = strdup(name);
      p->value = strdup(value);
      p->prev = VarHead;
      p->next = VarHead->next;
      p->next->prev = p;
      VarHead->next = p;
   }	
}


/****************************************************************************
 *
 * Function: VarDelete(char *)
 *
 * Purpose: deletes a defined variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
void VarDelete(char *name)
{
   struct VarEntry *p;


   if(! VarHead)
      return;

   p = VarHead;

   do
   {
      if(strcasecmp(p->name, name) == 0)
      {
         p->prev->next = p->next;
         p->next->prev = p->prev;

         if(VarHead == p)
            if((VarHead = p->next) == p)
               VarHead = NULL;

         if(p->name)
            free(p->name);

         if(p->value)
            free(p->value);

         free(p);

         return;
      }

      p = p->next;

   } while(p != VarHead);
}


/****************************************************************************
 *
 * Function: VarGet(char *)
 *
 * Purpose: get the contents of a variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: char * to contents of variable or NULL
 *
 ***************************************************************************/
char *VarGet(char *name) 
{
   struct VarEntry *p;


   if(! VarHead)
      return(NULL);

   p = VarHead;

   do 
   {
      if(strcasecmp(p->name, name) == 0)
         return(p->value);

      p = p->next;

   } while(p != VarHead);

   return(NULL);
}



/****************************************************************************
 *
 * Function: ExpandVars(char *)
 *
 * Purpose: expand all variables in a string
 *
 * Arguments: string => the name of the variable
 *
 * Returns: char * to the expanded string
 *
 ***************************************************************************/
char *ExpandVars(char *string) 
{
   static char estring[1024];
   char rawvarname[128],
        varname[128],
        varaux[128],
        varbuffer[128],
        varmodifier,
        *varcontents;
   int varname_completed,
       c, i, j, iv, jv,
       l_string,
       name_only;
 
 
   if(!string || ! *string || ! strchr(string, '$'))
      return(string);
 
   bzero(estring, sizeof(estring));
 
   i = j = 0;
   l_string = strlen(string);

   while(i < l_string && j < sizeof(estring) - 1)
   {
      c = string[i++];
      if(c == '$')
      {
         bzero(rawvarname, sizeof(rawvarname));
         varname_completed = 0;
         name_only = 1;
         iv = i;
         jv = 0;
 
         if(string[i] == '(')
         {
            name_only = 0;
            iv = i + 1;
         }
 
         while(!varname_completed 
               && iv < l_string 
               && jv < sizeof(rawvarname) - 1) 
         {
            c = string[iv++];

            if((name_only && !(isalnum(c) || c == '_')) 
               || (! name_only && c == ')')) 
            {
               varname_completed = 1;
 
               if(name_only)
                  iv--;
            } 
            else
            {
               rawvarname[jv++] = c;
            }
         }
 
         if(varname_completed) 
         {
            char *p;
 
            i = iv;
 
            varcontents = NULL;
 
            bzero(varname, sizeof(varname));
            bzero(varaux, sizeof(varaux));
            varmodifier = ' ';
 
            if((p = strchr(rawvarname, ':'))) 
            {
               strncpy(varname, rawvarname, p - rawvarname);
 
               if(strlen(p) >= 2)
               {
                  varmodifier = *(p + 1);
                  strcpy(varaux, p + 2);
               }
            }
            else
               strcpy(varname, rawvarname);
                                        
            bzero(varbuffer, sizeof(varbuffer));
 
            varcontents = VarGet(varname);
 
            switch(varmodifier)
            {
               case '-':
                  if(! varcontents || ! strlen(varcontents))
                     varcontents = varaux;
                  break;
 
               case '?':
                  if(! varcontents || ! strlen(varcontents)) 
                  {
                     fprintf(stderr, "ERROR %s (%d): ", file_name, file_line);
 
                     if(strlen(varaux))
                        fprintf(stderr, "%s\n", varaux);
                     else
                        fprintf(stderr, "Undefined variable \"%s\"\n", varname);
 
                     exit(1);
                  }
 
                  break;
            }
 
            if(varcontents)
            {
               int l_varcontents = strlen(varcontents);
 
               iv = 0;

               while(iv < l_varcontents && j < sizeof(estring) - 1)
                     estring[j++] = varcontents[iv++];
             }
          }
          else
            estring[j++] = '$';
       }
       else
         estring[j++] = c;
     }
 
   return(estring);
}




void Preprocess(Packet *p)
{
   PreprocessFuncNode *idx;

   do_detect = 1;
   idx = PreprocessList;

   while(idx != NULL)
   {
      idx->func(p);
      idx = idx->next;
   }

   if(!p->frag_flag && do_detect)
   {
      Detect(p);
   }
}


/**  D E T E C T I O N   E N G I N E   S T A R T S   H E R E  **/

/****************************************************************************
 *
 * Function: Detect()
 *
 * Purpose: Apply the three rules lists to the current packet
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void Detect(Packet *p)
{
#ifdef BENCHMARK
   cmpcount = 0;
#endif

   if(!pv.rules_order_flag)
   {
#ifdef DEBUG
      printf("[*] AlertList\n");
#endif
     if(!EvalPacket(&Alert, RULE_ALERT, p))
     {
#ifdef BENCHMARK
         printf(" **** cmpcount: %d **** \n", cmpcount); 
         cmpcount = 0;
#endif
#ifdef DEBUG
         printf("[*] PassList\n");
#endif
         if(!EvalPacket(&Pass, RULE_PASS, p))
         {
#ifdef BENCHMARK
            printf(" **** cmpcount: %d **** \n", cmpcount); 
            cmpcount = 0;
#endif
#ifdef DEBUG
            printf("[*] LogList\n");
#endif
            EvalPacket(&Log, RULE_LOG, p);
#ifdef BENCHMARK
            printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
         }
      }
   }
   else
   {
#ifdef DEBUG
      printf("[*] PassList\n");
#endif
      if(!EvalPacket(&Pass, RULE_PASS, p))
      {
#ifdef BENCHMARK
         printf(" **** cmpcount: %d **** \n", cmpcount); 
         cmpcount = 0;
#endif
#ifdef DEBUG
         printf("[*] AlertList\n");
#endif
         if(!EvalPacket(&Alert, RULE_ALERT, p))
         {
#ifdef BENCHMARK
            printf(" **** cmpcount: %d **** \n", cmpcount); 
            cmpcount = 0;
#endif
#ifdef DEBUG
            printf("[*] LogList\n");
#endif
            EvalPacket(&Log, RULE_LOG, p);
#ifdef BENCHMARK
            printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
         }
      }
   }
}



/****************************************************************************
 *
 * Function: EvalPacket(ListHead *, int )
 *
 * Purpose: Figure out which rule tree to call based on protocol
 *
 * Arguments: List => the rule list to check
 *            mode => the rule mode (alert, log, etc)
 *
 * Returns: 1 on a match, 0 on a miss
 *
 ***************************************************************************/
int EvalPacket(ListHead *List, int mode, Packet *p)
{
   RuleTreeNode *rtn_idx;

   /* figure out which list to look at */
   switch(p->iph->ip_proto)
   {
      case IPPROTO_TCP:
#ifdef DEBUG
         printf("Detecting on TcpList\n");
#endif
         rtn_idx = List->TcpList;
         break;

      case IPPROTO_UDP:
#ifdef DEBUG
         printf("Detecting on UdpList\n");
#endif
         rtn_idx = List->UdpList;
         break;

      case IPPROTO_ICMP:
#ifdef DEBUG
         printf("Detecting on IcmpList\n");
#endif
         rtn_idx = List->IcmpList;
         break;

      default: 
         rtn_idx = NULL;
         break;
   }

   return EvalHeader(rtn_idx, p);
}



/****************************************************************************
 *
 * Function: EvalHeader(RuleTreeNode *, Packet * )
 *
 * Purpose: Implement two dimensional recursive linked-list-of-function-pointers
 *          detection engine!  This part looks at the IP header info (and 
 *          ports if necessary) and decides whether or not to proceed down 
 *          the rule option chain.  Did I mention it's recursive?  For all
 *          you fans of the old goto system, sorry.... :)
 *
 * Arguments: rtn_idx => the rule block node to test
 *            p => ptr to the packet data structure
 *
 * Returns: 1 on a match, 0 on a miss
 *
 ***************************************************************************/
int EvalHeader(RuleTreeNode *rtn_idx, Packet *p)
{
   int rule_match = 0;

   if(rtn_idx == NULL)
   {
      return 0;
   }

#ifdef DEBUG
   printf("[*] Rule Head %d\n", rtn_idx->head_node_number);
#endif

   if(!rtn_idx->rule_func->RuleHeadFunc(p, rtn_idx, rtn_idx->rule_func))
   {
#ifdef DEBUG
      printf("   => Header check failed, checking next node\n");
#endif
      EvalHeader(rtn_idx->right, p);
#ifdef DEBUG
      printf("   => returned from next node check\n");
#endif
   }
   else
   {

#ifdef DEBUG
      printf("   => Got head match, checking options chain\n");
#endif

      rule_match = EvalOpts(rtn_idx->down, p);

      if(rule_match)
      {
#ifdef DEBUG
         printf("   => Got rule match, rtn_idx type = %d\n", rtn_idx->type);
#endif
         switch(rtn_idx->type)
         {
            case RULE_PASS: 
#ifdef DEBUG
               printf("   => Pass rule, returning...\n");
#endif

#ifdef BENCHMARK
               printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
               return 1;

            case RULE_ALERT: 
#ifdef DEBUG
               printf("   => Finishing alert packet!\n");
#endif

#ifdef BENCHMARK
               printf("        <!!> Check count = %d\n", check_count);
               check_count = 0;
               printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
               (*LogFunc)(p);
#ifdef DEBUG
               printf("   => Alert packet finished, returning!\n");
#endif

               return 1;

            case RULE_LOG: 
#ifdef DEBUG
               printf("   => Logging packet data and returning...\n");
#endif
               (*LogFunc)(p);

#ifdef BENCHMARK 
               printf("        <!!> Check count = %d\n", check_count);
               check_count = 0;
               printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
               return 1;
         }
      }

      if(!rule_match)
      {
#ifdef DEBUG
         printf("No match, continuing...\n");
#endif
         return EvalHeader(rtn_idx->right, p);
      }
   }
#ifdef BENCHMARK
   printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif

   return 0;


}


int CheckAddrPort(u_long addr, u_long mask, u_short hi_port, u_short lo_port, Packet *p, char flags, int mode)
{
   u_long  pkt_addr;
   u_short pkt_port;
   int     any_port_flag = 0;
   int     except_addr_flag = 0;
   int     except_port_flag = 0;


   /* set up the packet particulars */
   if((mode & CHECK_SRC)== CHECK_SRC)
   {
      pkt_addr = p->iph->ip_src.s_addr;
      pkt_port = p->sp;

      if((mode & INVERSE)==INVERSE)
      {
         if(flags & EXCEPT_DST_IP)
         {
            except_addr_flag = 1;
         }

         if(flags & ANY_DST_PORT)
         {
            any_port_flag = 1;
         }

         if(flags & EXCEPT_DST_PORT)
         {
            except_port_flag = 1;
         }
      }
      else
      {
         if(flags & EXCEPT_SRC_IP)
         {
            except_addr_flag = 1;
         }

         if(flags & ANY_SRC_PORT)
         {
            any_port_flag = 1;
         }

         if(flags & EXCEPT_SRC_PORT)
         {
            except_port_flag = 1;
         }
      }
   }
   else
   {
      pkt_addr = p->iph->ip_dst.s_addr;
      pkt_port = p->dp;

      if((mode & INVERSE)==INVERSE)
      {
         if(flags & EXCEPT_SRC_IP)
         {
            except_addr_flag = 1;
         }

         if(flags & ANY_SRC_PORT)
         {
            any_port_flag = 1;
         }

         if(flags & EXCEPT_SRC_PORT)
         {
            except_port_flag = 1;
         }
      }
      else
      {
         if(flags & EXCEPT_DST_IP)
         {
            except_addr_flag = 1;
         }

         if(flags & ANY_DST_PORT)
         {
            any_port_flag = 1;
         }

         if(flags & EXCEPT_DST_PORT)
         {
            except_port_flag = 1;
         }
      }
   }

   /* test the rule address vs. the packet address */
   if (!((addr == (pkt_addr & mask))
       ^ (except_addr_flag)))
   {
      return 0;
   }

   /* if the any port flag is up, we're all done (success)*/
   if(any_port_flag)
      return 1;

   /* check the packet port against the rule port */
   if((pkt_port > hi_port) || (pkt_port < lo_port))
   {
      /* if the exception flag isn't up, fail */
      if(!except_port_flag)
      {
         return 0;
      }
   }
   else
   {
      /* if the exception flag is up, fail */
      if(except_port_flag)
      {
         return 0;
      }
   }

   /* ports and address match */
   return 1;
}



/****************************************************************************
 *
 * Function: EvalOpts(OptTreeNode *, Packet *)
 *
 * Purpose: Implements section 2 of recursive detection engine.  Goes
 *          thru the options chain and see if the current packet matches
 *          any of the rules
 *
 * Arguments: List => the OTN list
 *            p => pointer to the packet data struct
 *
 * Returns: 1 on a match, 0 on no match
 *
 ***************************************************************************/
int EvalOpts(OptTreeNode *List, Packet *p)
{
   if(List == NULL)
      return 0;

#ifdef DEBUG
   printf("   => Checking Option Node %d\n", List->chain_node_number);
#endif

   if(List->opt_func == NULL)
   {
      fprintf(stderr, "List->opt_func was NULL on option #%d!\n", List->chain_node_number);
      exit(1);
   }

   if(!List->opt_func->OptTestFunc(p, List, List->opt_func))
   {
      if(EvalOpts(List->next, p))
         return 1;
      else
         return 0;
   }
   else
   {
      /* do the appropriate follow-on action */
      switch(List->type)
      {
         case RULE_PASS: 
            return 1;
                      
         case RULE_ALERT: 
            otn_tmp = List;

#ifdef DEBUG
            printf("        <!!> Generating alert! \"%s\"\n", List->message);
#endif
            (*AlertFunc)(p, List->message);
#ifdef DEBUG
            printf("        <!!> Finished, returning to calling function\n");
#endif

            return 1;

         case RULE_LOG: 
            otn_tmp = List;

            return 1;
      }
   }

   return  0;
}


/****************************************************************************
 *
 * Function: DumpChain(RuleTreeNode *, char *)
 *
 * Purpose: print out the chain lists by header block node group
 *
 * Arguments: rtn_idx => the RTN index pointer
 *            name => the name of the list being printed out 
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpChain(RuleTreeNode *rtn_head, char *name)
{
   RuleTreeNode *rtn_idx;
   OptTreeNode *otn_idx;

   printf("%s\n", name);

   rtn_idx = rtn_head;

   if(rtn_idx == NULL)
      printf("    Empty!\n\n");

   /* walk thru the RTN list */
   while(rtn_idx != NULL)
   {
      printf("Rule type: %d\n", rtn_idx->type);
      printf("SRC IP: 0x%.8lX / 0x%.8lX\n", rtn_idx->sip, rtn_idx->smask);
      printf("DST IP: 0x%.8lX / 0x%.8lX\n", rtn_idx->dip, rtn_idx->dmask);
      printf("SRC PORT: %d - %d \n", rtn_idx->lsp, rtn_idx->hsp);
      printf("DST PORT: %d - %d \n", rtn_idx->ldp, rtn_idx->hdp);
      printf("Flags: ");
      if(rtn_idx->flags & EXCEPT_SRC_IP) printf("EXCEPT_SRC_IP ");
      if(rtn_idx->flags & EXCEPT_DST_IP) printf("EXCEPT_DST_IP ");
      if(rtn_idx->flags & ANY_SRC_PORT) printf("ANY_SRC_PORT ");
      if(rtn_idx->flags & ANY_DST_PORT) printf("ANY_DST_PORT ");
      if(rtn_idx->flags & EXCEPT_SRC_PORT) printf("EXCEPT_SRC_PORT ");
      if(rtn_idx->flags & EXCEPT_DST_PORT) printf("EXCEPT_DST_PORT ");
      printf("\n");

      /* print the RTN header number */
      printf("Head: %d\n", rtn_idx->head_node_number);
      printf("      |\n");
      printf("       ->");

      otn_idx = rtn_idx->down;

      /* walk thru the OTN chain */
      while(otn_idx != NULL)
      {
         printf(" %d", otn_idx->chain_node_number);
         otn_idx = otn_idx->next;
      }
 
      printf("|=-\n");

      rtn_idx = rtn_idx->right;
   }
}



void IntegrityCheck(RuleTreeNode *rtn_head, char *listname)
{
   RuleTreeNode *rtn_idx = NULL;
   OptTreeNode *otn_idx;
   OptFpList   *ofl_idx;
   int opt_func_count;

   printf("%-20s: ", listname);

   if(rtn_head == NULL)
   {
      printf("Empty list...\n");
      return;
   }

   rtn_idx = rtn_head;

   while(rtn_idx != NULL)
   {
      otn_idx = rtn_idx->down;

      while(otn_idx != NULL)
      {
         ofl_idx = otn_idx->opt_func;
         opt_func_count = 0;

         while(ofl_idx != NULL)
         {
            opt_func_count++;
            
#ifdef DEBUG
            printf("%p->", ofl_idx->OptTestFunc);
#endif

            ofl_idx = ofl_idx->next;
         }

         if(opt_func_count == 0)
         {
            printf("Got Zero Length List, please tell Marty!\n");
#ifndef JUSTDOIT
            exit(1);
#endif
         }
#ifdef DEBUG
         printf("\n");
#endif

         otn_idx = otn_idx->next;
      }

      rtn_idx = rtn_idx->right;
   }

   printf("OK\n");
}



int CheckBidirectional(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   int test_result = 0;

#ifdef DEBUG
   printf("Checking bidirectional rule...\n");
#endif
   test_result = CheckAddrPort(rtn_idx->sip, rtn_idx->smask, rtn_idx->hsp, rtn_idx->lsp, p, rtn_idx->flags, CHECK_SRC);

   if(test_result)
   {
#ifdef DEBUG
      printf("   Src->Src check passed\n");
#endif
      test_result = CheckAddrPort(rtn_idx->dip, rtn_idx->dmask, rtn_idx->hdp,rtn_idx->ldp, p, rtn_idx->flags, CHECK_DST);

      if(!test_result)
      {
#ifdef DEBUG
         printf("   Dst->Dst check failed, checking inverse combination\n");
#endif
         /* dst mismatch on a src match might not mean failure */
         /* check the inverse */
         test_result = CheckAddrPort(rtn_idx->dip, rtn_idx->dmask, rtn_idx->hdp,rtn_idx->ldp, p, rtn_idx->flags, (CHECK_SRC|INVERSE));

         if(test_result)
         {
#ifdef DEBUG
            printf("   Inverse Dst->Src check passed\n");
#endif
            test_result = CheckAddrPort(rtn_idx->sip, rtn_idx->smask, rtn_idx->hsp, rtn_idx->lsp, p, rtn_idx->flags, (CHECK_DST|INVERSE));
                
            if(!test_result)
            {
#ifdef DEBUG
               printf("   Inverse Src->Dst check failed\n");
#endif
               /* no match */
               return 0;
            }
#ifdef DEBUG
            else
            {
               printf("Inverse addr/port match\n");
            }
#endif
         }
         else
         {
#ifdef DEBUG
            printf("   Inverse Dst->Src check failed, trying next rule\n");
#endif
            return 0;
         }
      }
#ifdef DEBUG
      else
      {
         printf("dest IP/port match\n");
      }
#endif
   }
   else
   {
#ifdef DEBUG
      printf("   Src->Src check failed, trying inverse test\n");
#endif
      test_result = CheckAddrPort(rtn_idx->dip, rtn_idx->dmask, rtn_idx->hdp,rtn_idx->ldp, p, rtn_idx->flags, CHECK_SRC|INVERSE);

      if(test_result)
      {
#ifdef DEBUG
         printf("   Dst->Src check passed\n");
#endif
         test_result = CheckAddrPort(rtn_idx->sip, rtn_idx->smask, rtn_idx->hsp, rtn_idx->lsp, p, rtn_idx->flags, CHECK_DST|INVERSE);
         
         if(!test_result)
         {
#ifdef DEBUG
            printf("   Src->Dst check failed\n");
#endif
            /* no match */
            return 0;
         }
#ifdef DEBUG
         else
         {
            printf("Inverse addr/port match\n");
         }
#endif
      }
      else
      {
#ifdef DEBUG
         printf("   Inverse test failed, testing next rule...\n");
#endif
         /* no match, give up and try the next rule */
         return 0;
      }
   }

   return 1;
}



/****************************************************************************
 *
 * Function: CheckSrcIpEqual(Packet *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the source IP and see if it equals the SIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckSrcIPEqual(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
#ifdef DEBUG
   printf("CheckSrcIPEqual: ");
#endif

   /* do the check */
   if(rtn_idx->sip == (p->iph->ip_src.s_addr & rtn_idx->smask))
   {
#ifdef DEBUG
      printf("  SIP match\n");
#endif
      /* the packet matches this test, proceed to the next test */
      return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf("  Mismatch on SIP\n");
   }
#endif

   /* return 0 on a failed test */
   return 0;
}



/****************************************************************************
 *
 * Function: CheckSrcIpNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the source IP and see if it's unequal to the SIP of the 
 *          packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckSrcIPNotEq(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
#ifdef DEBUG
   printf("CheckSrcIPNotEq: ");
#endif

   /* do the check */
   if(rtn_idx->sip != (p->iph->ip_src.s_addr & rtn_idx->smask))
   {
#ifdef DEBUG
      printf("  SIP exception match\n");
#endif
      /* the packet matches this test, proceed to the next test */
      return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf("  Mismatch on SIP\n");
   }
#endif

   /* return 0 on a failed test */
   return 0;
}



/****************************************************************************
 *
 * Function: CheckDstIpEqual(Packet *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the dest IP and see if it equals the DIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckDstIPEqual(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
#ifdef DEBUG
   printf("CheckDstIPEqual: ");
#endif

   /* same as above */
   if(rtn_idx->dip == (p->iph->ip_dst.s_addr & rtn_idx->dmask))
   {
#ifdef DEBUG
      printf("  DIP match\n");
#endif
      return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf("  Mismatch on DIP\n");
   }
#endif

   return 0;
}



/****************************************************************************
 *
 * Function: CheckDstIpNotEq(Packet *, struct _RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the dest IP and see if it equals the DIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckDstIPNotEq(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
#ifdef DEBUG
   printf("CheckDstIPNotEq: ");
#endif

   /* same as above */
   if(rtn_idx->dip != (p->iph->ip_dst.s_addr & rtn_idx->dmask))
   {
#ifdef DEBUG
      printf("  DIP exception match\n");
#endif
      return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf("  Mismatch on DIP\n");
   }
#endif

   return 0;
}



int CheckSrcPortEqual(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
#ifdef DEBUG
   printf("CheckSrcPortEqual: ");
#endif

   if((p->sp <= rtn_idx->hsp) && (p->sp >= rtn_idx->lsp))
   {
#ifdef DEBUG
      printf("  SP match!\n");
#endif
      return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf("   SP mismatch!\n");
   }
#endif

   return 0;
}





int CheckSrcPortNotEq(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
#ifdef DEBUG
   printf("CheckSrcPortNotEq: ");
#endif

   if((p->sp > rtn_idx->hsp) || (p->sp < rtn_idx->lsp))
   {
#ifdef DEBUG
      printf("  SP exception match!\n");
#endif
      return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf("   SP mismatch!\n");
   }
#endif

   return 0;
}





int CheckDstPortEqual(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
#ifdef DEBUG
   printf("CheckDstPortEqual: ");
#endif

   if((p->dp <= rtn_idx->hdp) && (p->dp >= rtn_idx->ldp))
   {
#ifdef DEBUG
      printf(" DP match!\n");
#endif

      return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf(" DP mismatch!\n");
   }
#endif

   return 0;
}




int CheckDstPortNotEq(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
#ifdef DEBUG
   printf("CheckDstPortNotEq: ");
#endif

   if((p->dp > rtn_idx->hdp) || (p->dp < rtn_idx->ldp))
   {
#ifdef DEBUG
      printf(" DP exception match!\n");
#endif

      return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf(" DP mismatch!\n");
   }
#endif

   return 0;
}



int RuleListEnd(Packet *p, struct _RuleTreeNode *rtn_idx, RuleFpList *fp_list)
{
   return 1;
}


int OptListEnd(Packet *p, struct _OptTreeNode *otn_idx, OptFpList *fp_list)
{
   return 1;
}
