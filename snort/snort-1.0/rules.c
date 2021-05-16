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

extern PrintIP pip; /* ptr to the printout struct global */

Rule *current;      /* util ptr for the current rule */
int file_line;      /* current line being processed in the rules file */
Rule *PassList;     /* List of Pass Rules */
Rule *LogList;      /* List of Log Rules */
Rule *AlertList;    /* List of Alert Rules */
int rule_count;


/****************************************************************************
 *
 * Function: ParseRulesFile(char *)
 *
 * Purpose:  Read the rules file a line at a time and send each rule to
 *           the rule parser
 *
 * Arguments: file => rules file filename
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRulesFile(char *file)
{
   FILE *thefp;       /* file pointer for the rules file */
   char buf[STD_BUF]; /* file read buffer */

#ifdef DEBUG
   printf("Opening rules file: %s\n", file);
#endif

   /* open the rules file */
   if((thefp = fopen(file,"r")) == NULL)
   {
      printf("Unable to open rules file: %s\n", file);
      exit(1);
   }

   /* clear the line buffer */
   bzero(buf, STD_BUF);

   /* loop thru each file line and send it to the rule parser */
   while((fgets(buf, STD_BUF, thefp)) != NULL)
   {
      /* inc the line counter so the error messages know which line to 
         bitch about */
      file_line++;

#ifdef DEBUG2
      printf("Got line %d: %s", file_line, buf);
#endif
      /* if it's not a comment or a <CR>, send it to the parser */
      if((buf[0] != '#') && (buf[0] != 0x0a) && (buf[0] != ';'))
      {
         ParseRule(buf);
      }

      bzero(buf, STD_BUF);
   }

   printf("System configured with %d rules.\n",rule_count);

#ifdef DEBUG
   DumpRuleList(AlertList);
   DumpRuleList(PassList);
   DumpRuleList(LogList);
#endif

   fclose(thefp);

   return;
}



/****************************************************************************
 *
 * Function: ParseRule(char *)
 *
 * Purpose:  Process an individual rule and add it to the rule list
 *
 * Arguments: rule => rule string
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRule(char *rule)
{
   char **toks;          /* dbl ptr for mSplit call, holds rule tokens */
   int num_toks;         /* holds number of tokens found by mSplit */
   int rule_type;        /* rule type enumeration variable */


   /* chop off the <CR/LF> from the string */
   strip(rule);

   /* break out the tokens from the rule string */
   toks = mSplit(rule, " ", 10, &num_toks,0);

   rule_type = RuleType(toks[0]);

   /* Make a rule node */
   CreateRuleNode(rule_type);
   rule_count++;
   current->rule_num = rule_count;
                       
   /* figure out what type (pass/log/alert) rule is being looked at */
   current->type = rule_type;
 
   /* set the rule protocol */
   current->proto = WhichProto(toks[1]);

   /* Process the IP address and CIDER netmask */
   /* if this is an "any" addr, set the flag */
   if(ParseIP(toks[2], (u_long *) &current->sip, (u_long *) &current->smask))
      current->flags |= ANY_SRC_IP;

   /* do the same for the port */
   if(ParsePort(toks[3], (u_short *) &current->hsp, (u_short *) &current->lsp, toks[1], 
               (int *) &current->not_sp_flag))
      current->flags |= ANY_SRC_PORT;

   if(ParseIP(toks[5], (u_long *) &current->dip, (u_long *) &current->dmask))
      current->flags |= ANY_DST_IP;

   if(ParsePort(toks[6], (u_short *) &current->hdp, (u_short *) &current->ldp, toks[1], 
                (int *) &current->not_sp_flag))
      current->flags |= ANY_DST_PORT;

   /* decode the rest of the rule content */

   ParseRuleOptions(rule);

   free(toks);

   return;
}



void ParseRuleOptions(char *rule)
{
   char **toks = NULL;
   int num_toks;
   char *idx;
   char *aux;
   int i;
   char **opts;
   int num_opts;

   idx = index(rule, '(');
   i = 0;

   if(idx != NULL)
   {
      idx++;
      aux = index(idx,')');
      *aux = 0;

#ifdef DEBUG
      printf("[*] Rule: %s\n", idx);
#endif

      /* seperate all the options out */
      toks = mSplit(idx, ";", 10, &num_toks,'\\');

#ifdef DEBUG
      printf("   Got %d tokens\n", num_toks);
#endif

      num_toks--;
      while(num_toks)
      {
#ifdef DEBUG
         printf("   option: %s\n", toks[i]);
#endif

         opts = mSplit(toks[i], ":", 4, &num_opts,'\\');
         
#ifdef DEBUG
         printf("   option name: %s\n", opts[0]);
         printf("   option args: %s\n", opts[1]);
#endif

         while(isspace(*opts[0])) opts[0]++;
	 if(!strcasecmp(opts[0], "content"))
         {
	    ParsePattern(opts[1]);
	 }
         else if(!strcasecmp(opts[0], "msg"))
	      {
		 ParseMessage(opts[1]);
	      }
	      else if(!strcasecmp(opts[0], "flags"))
	           {
		      ParseFlags(opts[1]);
		   }
	           else if(!strcasecmp(opts[0], "ttl"))
		        {
		           aux = opts[1];
	                   while(isspace(*aux)) aux++;
			   current->ttl = atoi(opts[1]);
#ifdef DEBUG
			   printf("Set TTL to %d\n", current->ttl);
#endif
			}
		        else if(!strcasecmp(opts[0], "itype"))
			     {
				ParseItype(opts[1]);
			     }
		             else if(!strcasecmp(opts[0], "icode"))
			          {
				     ParseIcode(opts[1]);
			          }
         free(opts);
	 --num_toks;
	 i++;
      }
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
   if(!strncasecmp(func, "log",3))
      return RULE_LOG;

   if(!strncasecmp(func, "alert",5))
      return RULE_ALERT;

   if(!strncasecmp(func, "pass",4))
      return RULE_PASS;

   
   printf("ERROR line %d => Unknown Rule action: %s\n", file_line, func);
   CleanExit();
  
   return 0;
}

      

/****************************************************************************
 *
 * Function: CreateRuleNode(int)
 *
 * Purpose:  Allocate space for a rule and attach it to the end of the
 *           program rule list
 *
 * Arguments: type => the current rule type (pass/alert/log)
 *
 * Returns: void function
 *
 ***************************************************************************/
void CreateRuleNode(int type)
{
   Rule *idx;  /* index ptr for walking the rules list */

   idx = PassList;

   /* alloc a new rule */
   current = (Rule *) malloc(sizeof(Rule));

   if(current == NULL)
   {
      perror("CreateRuleNode()");
      exit(1);
   }

   /* clear the next ptr */
   current->next = NULL;
  
   /* figure out which list the current rule should be added to */
   switch(type)
   {
      case RULE_LOG: if(LogList == NULL)
                     {
                        LogList = current;
                        return;
                     }
                     else
                     {
                        idx = LogList;
                     }

                     break;

      case RULE_PASS: if(PassList == NULL)
                      {
                         PassList = current;
                         return;
                      }
                      else
                      {
                         idx = PassList;
                      }

                      break;

      case RULE_ALERT: if(AlertList == NULL)
                       {
                          AlertList = current;
                          return;
                       }
                       else
                       {
                          idx = AlertList;
                       }
                       break;
   }

   /* loop thru the list and add the current rule to the end */
   while(idx->next != NULL)
   {
      idx = idx->next;
   }

   idx->next = current;

   return;
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

   fprintf(stderr, "ERROR Line %d => Bad protocol: %s\n", file_line, proto_str);
   exit(1);
}


/****************************************************************************
 *
 * Function: ParseIP(char *, u_long *, u_long *)
 *
 * Purpose: Convert a supplied IP address to it's network order 32-bit long
 *          value.  Also convert the CIDER block notation into a real 
 *          netmask. 
 *
 * Arguments: addr => address string to convert
 *            ip_addr => storage point for the converted ip address
 *            netmask => storage point for the converted netmask
 *
 * Returns: 0 for normal addresses, 1 for an "any" address
 *
 ***************************************************************************/
int ParseIP(char *addr, u_long *ip_addr, u_long *netmask)
{
   char **toks;                /* token dbl buffer */
   int num_toks;               /* number of tokens found by mSplit() */
   int nmask;                  /* netmask temporary storage */
   struct hostent *host_info;  /* various struct pointers for stuff */
   struct sockaddr_in sin;     /* addr struct */

   /* check for wildcards */
   if(!strncasecmp(addr, "any", 3))
   {
      *ip_addr = 0;
      *netmask = 0;
      return 1;
   }
 
   /* break out the CIDER notation from the IP address */
   toks = mSplit(addr,"/",2,&num_toks,0);

   if(num_toks != 2)
   {
      fprintf(stderr, "ERROR Line %d => No netmask specified for IP address %s\n", file_line, addr);
      exit(1);
   }

   /* convert the CIDER notation into a real live netmask */
   nmask = 32 - atoi(toks[1]);

   *netmask = pow(2, nmask) - 1;
   *netmask = -(*netmask);
   *netmask -= 1;

#ifndef WORDS_BIGENDIAN
   /* since PC's store things the "wrong" way, shuffle the bytes into
      the right order */
   *netmask = htonl(*netmask);
#endif

   /* convert names to IP addrs */
   if(isalpha(toks[0][0]))
   {
      /* get the hostname and fill in the host_info struct */
      if((host_info = gethostbyname(toks[0])))
      {
         bcopy(host_info->h_addr, (char *)&sin.sin_addr, host_info->h_length);
      }
      else if((sin.sin_addr.s_addr = inet_addr(toks[0])) == INADDR_NONE)
      {
         fprintf(stderr,"ERROR Line %d => Couldn't resolve hostname %s\n", 
                 file_line, toks[0]);
         exit(1);
      }

      *ip_addr = ((u_long)(sin.sin_addr.s_addr) & (*netmask));
      return 1;
   }

   /* convert the IP addr into its 32-bit value */
   if((*ip_addr = inet_addr(toks[0])) == -1)
   {
      fprintf(stderr, "ERROR Line %d => Rule IP addr (%s) didn't x-late, WTF?\n",
              file_line, toks[0]);
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
 * Arguments: rule_port => port string
 *            port => converted integer value of the port
 *
 * Returns: 0 for a normal port number, 1 for an "any" port
 *
 ***************************************************************************/
int ParsePort(char *rule_port, u_short *hi_port, u_short *lo_port, char *proto, int *not_flag)
{
   char **toks;                /* token dbl buffer */
   int num_toks;               /* number of tokens found by mSplit() */

   *not_flag = 0;

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
               fprintf(stderr, "ERROR Line %d => port conversion failed on \"%s\"\n",
                       file_line, rule_port);
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
   if(isalpha(port[0]) != 0)
   {
      service_info = getservbyname(port, proto);
 
      if(service_info != NULL)
      {
         conv = ntohs(service_info->s_port);
         return conv; 
      }
      else
      {
         fprintf(stderr, "ERROR Line %d => getservbyname() failed on \"%s\"\n",
                 file_line, port);
         exit(1);
      }
   }

   if(!isdigit(port[0]))
   {
      fprintf(stderr, "ERROR Line %d => Invalid port: %s\n", file_line, port);
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
      fprintf(stderr, "ERROR Line %d => bad port number: %s", file_line, port);
      exit(1);
   }
}
 



/****************************************************************************
 *
 * Function: ApplyRules()
 *
 * Purpose: Apply the three rules lists to the current packet
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void ApplyRules()
{
   if(!pv.rules_order_flag)
   {
#ifdef DEBUG
      printf("[*] AlertList\n");
#endif
      if(!CheckRules(AlertList))
      {
#ifdef DEBUG
         printf("[*] PassList\n");
#endif
         if(!CheckRules(PassList))
         {
#ifdef DEBUG
            printf("[*] LogList\n");
#endif
            CheckRules(LogList);
         }
      }
   }
   else
   {
#ifdef DEBUG
      printf("[*] PassList\n");
#endif
      if(!CheckRules(PassList))
      {
#ifdef DEBUG
         printf("[*] AlertList\n");
#endif
         if(!CheckRules(AlertList))
         {
#ifdef DEBUG
            printf("[*] LogList\n");
#endif
            CheckRules(LogList);
         }
      }
   }
}


/****************************************************************************
 *
 * Function: CheckRules(Rule *)
 *
 * Purpose:  Test the current packet against the rule list to classify it.
 *
 * Arguments: list => the list to test the current packet against
 *
 * Returns: 0 if the packet doesn't match any of the rules in 
 *          the current list
 *
 *          1 if the current packet matches a rule in the list
 *
 ***************************************************************************/
int CheckRules(Rule *list)
{
   Rule *idx;  /* index ptr for walking the rules list */

   /* set the start ptr */
   idx = list;

   /* so I'm using goto's, so friggin what */
   /* you gotta problem with that jerky? (you lookin' at me?) */
   while(idx != NULL)
   {
#ifdef DEBUG
      printf("   Rule: %d\n", idx->rule_num);
#endif

      if(idx->proto != net.proto)
      {
#ifdef DEBUG
         printf("     Proto mismatch\n");
#endif 
         goto bottom;
      }
#ifdef DEBUG
      else
      {
         printf("     Proto match\n");
      }
#endif
      if((idx->flags & ANY_SRC_IP) || 
         (idx->sip == (net.sip & idx->smask)))
      {
#ifdef DEBUG
            printf("     SIP match\n");
#endif
      }
      else
      {
#ifdef DEBUG
            printf("     SIP mismatch\n");
#endif
         goto bottom;
      }

      if((idx->flags & ANY_SRC_PORT) ||
         ((idx->hsp>=net.sp)&&(idx->lsp<=net.sp)))
      {
#ifdef DEBUG
               printf("     SP match\n");
#endif
      }
      else
      {
#ifdef DEBUG
               printf("     SP mismatch\n");
#endif

         goto bottom;
      }

      if((idx->flags & ANY_DST_IP) ||
         (idx->dip == (net.dip & idx->dmask)))
      {
#ifdef DEBUG
         printf("     DIP match\n");
#endif
      }
      else
      {
#ifdef DEBUG
         printf("     DIP mismatch\n");
#endif
         goto bottom;
      }

      if((idx->flags & ANY_DST_PORT) ||
         ((idx->hdp>=net.dp)&&(idx->ldp<=net.dp)))
      {
#ifdef DEBUG
         printf("     DP match\n");
#endif
      }
      else
      {
#ifdef DEBUG
         printf("     DP mismatch %d-%d:%d\n", idx->ldp, idx->hdp, net.dp);
#endif
         goto bottom;
      }

      if(net.proto == IPPROTO_TCP)
      {
#ifdef DEBUG
         printf("     Proto is TCP, check_tcp_flags is %d\n", idx->check_tcp_flags);
#endif
         if(idx->check_tcp_flags)
         {
#ifdef DEBUG
            printf("     comparing flags %X => %X\n", idx->tcp_flags, net.tcp_flags);
	    fflush(stdout);
#endif
            if(idx->tcp_flags == net.tcp_flags) 
            {
#ifdef DEBUG
               printf("     TCP Flags match\n");
	    fflush(stdout);
#endif
            }
            else
            {
#ifdef DEBUG
               printf("     TCP Flags DO NOT match\n");
	    fflush(stdout);
#endif
               goto bottom;
            }
         }
      }
#ifdef DEBUG
      else
      {
         printf("     Proto is NOT TCP\n");
      }
#endif

      if(idx->ttl)
      {
#ifdef DEBUG
	 printf("Checking TTL value %d:%d\n", idx->ttl, pip.ttl);
#endif
	 if(pip.ttl == idx->ttl)
	 {
#ifdef DEBUG
            printf("TTL value matches!\n");
#endif
	 }
	 else
	 {
#ifdef DEBUG
            printf("TTL value does not match!\n");
#endif
            goto bottom;
	 }
      }

      if(idx->use_icmp_type)
      {
#ifdef DEBUG
	 printf("testing ICMP type %d:%d\n",idx->icmp_type,pip.icmp_type );
#endif
	 if(idx->icmp_type != pip.icmp_type)
	 {
#ifdef DEBUG
	    printf("ICMP type mismatch\n");
#endif
            goto bottom;
	 }
      }

      if(idx->use_icmp_code)
      {
	 if(idx->icmp_code != pip.icmp_code)
	 {
            goto bottom;
	 }
      }

      if(idx->pattern_size > 0)
      {
#ifdef DEBUG
         printf("     Attempting pattern match!\n");
#endif
         if(mSearch(pip.data,pip.dsize,idx->pattern_buf, idx->pattern_size))
         {
#ifdef DEBUG
            printf("     PATTERN MATCH!!\n");
#endif
         }
         else
         {
#ifdef DEBUG
            printf("     Pattern match failed!\n");
#endif
            goto bottom;
         }
      }

      current = idx;

      switch(idx->type)
      {
         case RULE_PASS: 
                       return 1;
                      
         case RULE_ALERT: AlertPkt();
                          return 1;

         case RULE_LOG: LogPkt();
                        return 1;
      }
bottom:
      idx = idx->next;
#ifdef DEBUG
      fflush(stdout);
#endif
   } 

   return 0;
}   



/****************************************************************************
 *
 * Function: DumpRuleList(Rule *)
 *
 * Purpose: Debug function, displays the rule list
 *
 * Arguments: list => the list to display
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpRuleList(Rule *list)
{
   Rule *idx;
   struct in_addr temp;

   idx = list;

   while(idx != NULL)
   {
      printf("RULE: # -> %d", idx->rule_num);
      printf("      type=%d\n",idx->type);
      printf("      proto=%d\n", idx->proto);
      temp.s_addr = idx->sip;
      printf("      %s:%d-%d ",inet_ntoa(temp),idx->lsp, idx->hsp);
      temp.s_addr = idx->dip;
      printf("-> %s:%d-%d\n",inet_ntoa(temp), idx->ldp, idx->hdp);
      printf("      flags= ");
      if(idx->flags & ANY_SRC_IP)
         printf("ANY_SRC_IP  ");
      if(idx->flags & ANY_SRC_PORT)
         printf("ANY_SRC_PORT  ");
      if(idx->flags & ANY_DST_IP)
         printf("ANY_DST_IP  ");
      if(idx->flags & ANY_DST_PORT)
         printf("ANY_DST_PORT ");
      if(idx->flags & ANY_FLAGS)
         printf("ANY_FLAGS");
      printf("\n");

      if(idx->proto == IPPROTO_TCP)
      {
         printf("      Check TCP flags = %d\n", idx->check_tcp_flags);
         printf("      TCP Flags= ");
         if(idx->tcp_flags & TH_FIN) printf("F"); else printf("*");
         if(idx->tcp_flags & TH_SYN) printf("S"); else printf("*");
         if(idx->tcp_flags & TH_RST) printf("R"); else printf("*");
         if(idx->tcp_flags & TH_PUSH) printf("P"); else printf("*");
         if(idx->tcp_flags & TH_ACK) printf("A"); else printf("*");
         if(idx->tcp_flags & TH_URG) printf("U"); else printf("*");
         printf("\n");
      }

      if(idx->use_icmp_type)
      {
	 printf("     ICMP type: %d\n", idx->icmp_type);
      }

      if(idx->use_icmp_code)
      {
	 printf("     ICMP code: %d\n", idx->icmp_code);
      }

      printf("      TTL: %d\n", idx->ttl);

      if(idx->message != NULL)
      {
         printf("      message: %s\n", idx->message);
      }

      if(idx->pattern_buf != NULL)
      {
         printf("      pattern size = %d\n", idx->pattern_size);
    
         printf("      pattern buffer: \n");
         PrintNetData(stdout, idx->pattern_buf, idx->pattern_size);
         ClearDumpBuf();
      }

      idx = idx->next;
   }
}
 





/****************************************************************************
 *
 * Function: ParsePattern(char *)
 *
 * Purpose: Process the application layer patterns and attach them to the
 *          appropriate rule.  My god this is ugly code.
 *
 * Arguments: rule => the rule string 
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParsePattern(char *rule)
{
   /* got enough ptrs for you? */
   char *start_ptr;
   char *end_ptr;
   char *idx;
   char *dummy_buf;
   char *dummy_idx;
   char *dummy_end;
   char hex_buf[9];
   u_int dummy_size = 0;
   unsigned int size;
   int hexmode = 0;
   int hexsize = 0;
   int pending = 0;
   int cnt = 0;

   start_ptr = index(rule,'"');

   if(start_ptr == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Content data needs to be enclosed in quotation marks (\")!\n", file_line);
      exit(1);
   }

   start_ptr++;
   

   end_ptr = index(start_ptr, '"');

   if(end_ptr == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Content data needs to be enclosed in quotation marks (\")!\n", file_line);
      exit(1);
   }

   *end_ptr = 0;
   size = end_ptr - start_ptr;
   
   if(size <= 0)
   {
      fprintf(stderr, "ERROR Line %d => Bad pattern length!\n", file_line);
      exit(1);
   }

   dummy_buf = (char *) malloc(sizeof(char)*size);

   if(dummy_buf == NULL)
   {
      fprintf(stderr, "ERROR => ParsePattern() buf malloc failed!\n");
      perror("malloc()");
      exit(1);
   }

   idx = start_ptr;
   dummy_idx = dummy_buf;
   dummy_end = (dummy_idx + size);

   bzero(hex_buf, 9);
   bzero(dummy_buf, size);
   memset(hex_buf, '0', 8);

   while(idx < end_ptr)
   {
      if(!hexmode)
      {
         if(*idx == '|')
         {
            hexmode = 1;
            hexsize = 0;
         }
         else
         {
            if(*idx >= 0x20 && *idx <= 0x7D)
            {
               if(dummy_idx < dummy_end)
               {
                  if(*idx != '\\')
		  {
                     dummy_buf[dummy_size] = start_ptr[cnt];
                     dummy_size++;
		  }
               }
               else
               {
                  fprintf(stderr, "ERROR => ParsePattern() dummy buffer overflow!\n");
                  exit(1);
               }
            }
	    else
	    {
               fprintf(stderr, "ERROR => character value out of range, try a binary buffer dude\n");
	       exit(1);
	    }
         }
      }
      else
      {
         if(*idx == '|')
         {
            hexmode = 0;

            if(!hexsize)
            {
               dummy_buf[dummy_size] = '|';
               dummy_size++;
            }
         }
         else
         {
            if(isxdigit(*idx))
            {
               hexsize++;

               if(!pending)
               {
                  hex_buf[7] = *idx;
                  pending++;
               }
               else
               {
                  hex_buf[8] = *idx;
                  pending--;

                  if(dummy_idx < dummy_end)
                  {
                     dummy_buf[dummy_size] = (u_long) strtol(hex_buf, (char **)NULL, 16);

                     dummy_size++;
                     bzero(hex_buf, 9);
                     memset(hex_buf, '0', 8);
                  }
                  else
                  {
                     fprintf(stderr, "ERROR => ParsePattern() dummy buffer overflow!\n");
                     exit(1);
                  }
               }
            }
            else
            {
               if(*idx != ' ')
               {
                  fprintf(stderr, "ERROR Line %d => Serious weirdness in binary buffer!\n", file_line);
                  exit(1);
               }
            }
         }
      }

      dummy_idx++;
      idx++;
      cnt++;
   }

/*   if(*idx >= 0x20 && *idx <= 0x7D)
   {
      if(dummy_idx < dummy_end)
      {
         dummy_buf[dummy_size] = start_ptr[cnt];
         dummy_size++;
      }
   }
*/
   if((current->pattern_buf=(char *)malloc(sizeof(char)*dummy_size))==NULL)
   {
      fprintf(stderr, "ERROR => ParsePattern() pattern_buf malloc filed!\n");
      exit(1);
   }

   memcpy(current->pattern_buf, dummy_buf, dummy_size);

   current->pattern_size = dummy_size;

   bzero(dummy_buf, dummy_size);
   free(dummy_buf);


   return;
}  



/****************************************************************************
 *
 * Function: Parseflags(char *)
 *
 * Purpose: Figure out which TCP flags the current rule is interested in
 *
 * Arguments: rule => the rule string 
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseFlags(char *rule)
{
   char *fptr;
   char *fend;
   
   fptr = rule;

   while(!isalnum((char) *fptr))
	   fptr++;

   current->tcp_flags = 0;
   current->check_tcp_flags = 1;

   /* find the end of the alert string */
   fend = fptr + strlen(fptr); 

   while(fptr < fend)
   {
      switch((*fptr&0xFF))
      {
         case 'f':
         case 'F':
                 current->tcp_flags |= R_FIN;
                 break;

         case 's':
         case 'S':
                 current->tcp_flags |= R_SYN;
                 break;

         case 'r':
         case 'R':
                 current->tcp_flags |= R_RST;
                 break;

         case 'p':
         case 'P':
                 current->tcp_flags |= R_PSH;
                 break;

         case 'a':
         case 'A':
                 current->tcp_flags |= R_ACK;
                 break;

         case 'u':
         case 'U':
                 current->tcp_flags |= R_URG;
                 break;

         case '0':
		 current->tcp_flags = 0;
                 current->check_tcp_flags = 1;
		 break;

         default:
                 fprintf(stderr, "ERROR Line %d: bad TCP flag = \"%c\"\n", file_line, *fptr);
                 fprintf(stderr, "      Valid otions: UAPRSF or 0 for NO flags (e.g. NULL scan)\n");
                 exit(1);
      }

      fptr++;
   }

}




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

   while(isspace((char) *ptr)) ptr++;

   /* find the end of the alert string */
   size = strlen(msg);

   /* alloc space for the string and put it in the rule */
   if(size > 0)
   {
      current->message = (char *)malloc((sizeof(char)*size));
      strncpy(current->message, ptr, size);
      current->message[size-1] = 0;
   }
   else 
   {
      fprintf(stderr, "ERROR Line %d: bad alert message size %d\n", file_line, size);
   }
}



void ParseItype(char *number)
{
   char *type;

   type = number;

   while(isspace(*type))
      type++;

   if(isdigit(*type))
   {
      current->icmp_type = atoi(type);

      if((current->icmp_type > 18)||
	 (current->icmp_type < 0))
      {
         fprintf(stderr, "ERROR Line %d: Bad ICMP type: %s\n", file_line, type);
	 exit(1);
      }
	      
      current->use_icmp_type = 1;	      
      return;
   }
   else
   {
      fprintf(stderr, "ERROR Line %d: Bad ICMP type: %s\n", file_line, type);
      exit(1);
   }  
}



void ParseIcode(char *type)
{
   while(isspace(*type))
      type++;

   if(isdigit(*type))
   {
      current->icmp_code = atoi(type);

      if((current->icmp_code > 15)||
	 (current->icmp_code < 0))
      {
         fprintf(stderr, "ERROR Line %d: Bad ICMP code: %s\n", file_line, type);
	 exit(1);
      }
      current->use_icmp_code = 1;	      
      return;
   }
   else
   {
      fprintf(stderr, "ERROR Line %d: Bad ICMP code: %s\n", file_line, type);
      exit(1);
   }  
}
