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

#include "log.h"

extern PrintIP pip;      /* we need this to log properly */
extern Rule *current;    /* current rule pointer */
char *data_dump_buffer;  /* printout buffer for PrintNetData */
int dump_ready;          /* flag to indicate status of printout buffer */
int dump_size;


/****************************************************************************
 *
 * Function: OpenLogFile()
 *
 * Purpose: Create the log directory and file to put the packet log into
 *
 * Arguments: None.
 *
 * Returns: 0 on success, exits on error
 *
 ****************************************************************************/
int OpenLogFile(int mode)
{
   char log_path[STD_BUF]; /* path to log file */
   char log_file[STD_BUF]; /* name of log file */
   char proto[5];          /* logged packet protocol */
#ifdef DEBUG
   struct in_addr temp;
#endif


   /* zero out our buffers */
   bzero(log_path, STD_BUF);
   bzero(log_file, STD_BUF);
   bzero(proto, 5);

   if(mode == DUMP)
   {
      sprintf(log_file, "%s/PACKET_FRAG", pv.log_dir);

      if((log_ptr = fopen(log_file, "a")) == NULL)
      {
          fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n",
                  log_file, strerror(errno));
          exit(1);
      }

      return 0;
   }

   if(mode == BOGUS)
   {
      sprintf(log_file, "%s/PACKET_BOGUS", pv.log_dir);

      if((log_ptr = fopen(log_file, "a")) == NULL)
      {
          fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n",
                  log_file, strerror(errno));
          exit(1);
      }

      return 0;
   }

   if(mode == NON_IP)
   {
      sprintf(log_file, "%s/PACKET_NONIP", pv.log_dir);

      if((log_ptr = fopen(log_file, "a")) == NULL)
      {
          fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n",
                  log_file, strerror(errno));
          exit(1);
      }

      return 0;
   }

   /* figure out which way this packet is headed in relation to the homenet */
   if((net.dip & pv.netmask) == pv.homenet)
   {
      if((net.sip & pv.netmask) != pv.homenet)
      {
         sprintf(log_path, "%s/%s", pv.log_dir, pip.saddr);
      }
      else
      {
         if( net.sp >= net.dp )
         {
            sprintf(log_path, "%s/%s", pv.log_dir, pip.saddr);
         }
         else
         {
            sprintf(log_path, "%s/%s", pv.log_dir, pip.daddr);
         }
      }
   }
   else
   {
#ifdef DEBUG
      temp.s_addr = net.sip & pv.netmask;
      printf("net.sip = %s, ", inet_ntoa(temp));

      temp.s_addr = pv.homenet;
      printf("homenet = %s\n", inet_ntoa(temp));
#endif

      if((net.sip & pv.netmask) == pv.homenet)
      {
         sprintf(log_path, "%s/%s", pv.log_dir, pip.daddr);
      }
      else
      {
         if(net.sp >= net.dp)
         {
            sprintf(log_path, "%s/%s", pv.log_dir, pip.saddr);
         }
         else
         {
            sprintf(log_path, "%s/%s", pv.log_dir, pip.daddr);
         }
      }
   }

#ifdef DEBUG
   fprintf(stderr, "Creating directory: %s\n",log_path);
#endif

   /* build the log directory */
   if(mkdir(log_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
   {
#ifdef DEBUG
      if(errno != EEXIST)
      {
         printf("Problem creating directory %s\n",log_path);
      }
#endif
   }

#ifdef DEBUG
   printf("Directory Created!\n");
#endif

   /* build the log filename */
   if((!strcasecmp(pip.proto, "TCP"))||
      (!strcasecmp(pip.proto, "UDP")))
   {
      if(pip.frag_off)
      {
         sprintf(log_file, "%s/IP_FRAG", log_path);
      }
      else
      {
         if(pip.sport >= pip.dport)
         {
            sprintf(log_file, "%s/%s:%d-%d", log_path, pip.proto, pip.sport,
                    pip.dport);
         }
         else
         {
            sprintf(log_file, "%s/%s:%d-%d", log_path, pip.proto, pip.dport,
                    pip.sport);
         }
      }
   }
   else
   {
      if(pip.frag_off)
      {
         sprintf(log_file, "%s/IP_FRAG", log_path);
      }
      else
      {
         if(!strcasecmp(pip.proto, "ICMP"))
         {
            sprintf(log_file, "%s/%s_%s", log_path, pip.proto, pip.icmp_str);
         }
      }
   }

#ifdef DEBUG
   printf("Opening file: %s\n", log_file);
#endif

   /* finally open the log file */
   if((log_ptr = fopen(log_file, "a")) == NULL)
   {
       fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n",
               log_file, strerror(errno));
       exit(1);
   }

#ifdef DEBUG
   printf("File opened...\n");
#endif

   return 0;
}



/****************************************************************************
 *
 * Function: PrintNetData(FILE *, char *,int)
 *
 * Purpose: Do a side by side dump of a buffer, hex dump of buffer bytes on
 *          the left, decoded ASCII on the right.
 *
 * Arguments: fp => ptr to stream to print to
 *            start => pointer to buffer data
 *            len => length of data buffer
 *
 * Returns: void function
 *
 ****************************************************************************/
void PrintNetData(FILE *fp, char *start, const int len)
{
   char *end;              /* ptr to buffer end */
   int i;                  /* counter */
   int j;                  /* counter */
   int dbuf_size;          /* data buffer size */
   int done;               /* flag */
   char *data;             /* index pointer */
   char *frame_ptr;        /* we use 66 byte frames for a printed line */
   char *d_ptr;            /* data pointer into the frame */
   char *c_ptr;            /* char pointer into the frame */
   char conv[] = "0123456789ABCDEF"; /* xlation lookup table */

   /* initialization */
   done = 0;

   if(start == NULL)
   {
      printf("Got NULL ptr in PrintNetData()\n");
      return;
   }

   /* zero, print a <CR> and get out */
   if(!len)
   {
      fputc('\n', fp);
      return;
   }

   /* if we've already prepared this particular data buffer, just print it 
      out again to save time */
   if(dump_ready)
   {
      fwrite(data_dump_buffer, dump_size, 1, fp);
      fflush(fp);
      return;
   }

   end = start + (len-1); /* set the end of buffer ptr */

   /* figure out how big the printout data buffer has to be */
   dbuf_size = ((len/16) * 66) + 67;

   /* generate the buffer */
   data_dump_buffer = (char *) malloc(dbuf_size);

   /* make sure it got allocated properly */   
   if(data_dump_buffer == NULL)
   {
      fprintf(stderr, "Failed allocating %X bytes!\n", dbuf_size);
      perror("PrintNetData()");
      CleanExit();
   }

   /* clean it out */
   memset(data_dump_buffer, 0x20, dbuf_size);


   /* set the byte buffer pointer to step thru the data buffer */
   data = start;

   /* set the frame pointer to the start of the printout buffer */
   frame_ptr = data_dump_buffer;

   /* loop thru the whole buffer */
   while(!done)
   {
      /* initialize counters and frame index pointers */
      i = 0;
      j = 0;
      d_ptr = frame_ptr;
      c_ptr = (frame_ptr + C_OFFSET);

      /* process 16 bytes per frame */
      for(i=0; i<16; i++)
      {
         /* look up the ASCII value of the first nybble of the 
            current data buffer */
         *d_ptr = conv[((*data&0xFF) >> 4)];
         d_ptr++;

         /* look up the second nybble */
         *d_ptr = conv[((*data&0xFF)&0x0F)];
         d_ptr++;

         /* put a space in between */
         *d_ptr = 0x20;
         d_ptr++;

         /* print out the char equivalent */
         if(*data > 0x20 && *data < 0x7E)
            *c_ptr = (*data&0xFF);
         else
            *c_ptr = 0x2E;

         c_ptr++;
 
         /* increment the pointer or finish up */
         if(data < end)
            data++;
         else
         {
            /* finish up the buffer printout and set the "ready" flags */
            done = 1;
            dump_ready = 1;

            *c_ptr='\n';
            c_ptr++;
            *c_ptr='\n';
            c_ptr++;
            *c_ptr = 0;

            dump_size = (int) (c_ptr - data_dump_buffer);
            fwrite(data_dump_buffer, dump_size, 1, fp);
            /*fflush(fp);*/
            return;
         }
      }

      *c_ptr = '\n';
      frame_ptr += FRAME_SIZE;
   }
}



/****************************************************************************
 *
 * Function: PrintIPPkt(FILE *, int, char *, int)
 *
 * Purpose: Dump the packet to the stream pointer
 *
 * Arguments: fp => pointer to print data to
 *            type => packet protocol
 *            data_ptr => pointer to the application layer data
 *            data_len => size of the app layer data
 *
 * Returns: void function
 *
 ****************************************************************************/
void PrintIPPkt(FILE *fp, int type)
{
#ifdef DEBUG
   printf("PrintIPPkt type = %d\n", type);
#endif

   /* dump the timestamp */
   fprintf(fp, "%s ", pip.timestamp);

   /* dump the ethernet header if we're doing that sort of thing */
   if(pv.showeth_flag)
   {
      PrintEthHeader(fp);
   }

   /* etc */
   PrintIPHeader(fp);

   /*if this isn't a fragment, print the other header info */
   if(!(pip.frag_off || pip.ip_mf))
   {
      switch(net.proto)
      {
         case IPPROTO_TCP:
                   PrintTCPHeader(fp);
                   break;

         case IPPROTO_UDP:
                   PrintUDPHeader(fp);
                   break;

         case IPPROTO_ICMP:
                   PrintICMPHeader(fp);
                   break;

         default: break;
      }
   }

   /* dump the application layer data */
   if(pv.data_flag)
      PrintNetData(fp, pip.data, pip.dsize); 
}




/****************************************************************************
 *
 * Function: OpenAlertFile()
 *
 * Purpose: Set up the file pointer/file for alerting
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void OpenAlertFile()
{
   char filename[STD_BUF];

   sprintf(filename, "%s/alert", pv.log_dir);

   if((alert = fopen(filename, "a")) == NULL)
   {
       fprintf(stderr, "ERROR in OpenAlertFile() => fopen() alert file: %s\n",
               strerror(errno));
       exit(1);
   }
} 



/****************************************************************************
 *
 * Function: ClearDumpBuf()
 *
 * Purpose: Clear out the buffer that PrintNetData() generates
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void ClearDumpBuf()
{
   if(data_dump_buffer != NULL)
      free(data_dump_buffer);

   data_dump_buffer = NULL;

   dump_ready = 0;
}



/****************************************************************************
 *
 * Function: AlertPkt()
 *
 * Purpose: Send the current packet to the alert file
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void AlertPkt()
{
   /* new syslog output option code at the end... */
   if(!pv.syslog_flag)
   {
      OpenAlertFile();

      if(current->message != NULL)
         fprintf(alert, "[**] %s [**]\n", current->message);

      fprintf(alert, "%s ", pip.timestamp);

      if(pv.showeth_flag)
      {
         PrintEthHeader(alert);
      }

      PrintIPHeader(alert);

      /*if this isn't a fragment, print the other header info */
      if(!(pip.frag_off || pip.ip_mf))
      {
         switch(net.proto)
         {
            case IPPROTO_TCP:
                      PrintTCPHeader(alert);
                      break;

            case IPPROTO_UDP:
                      PrintUDPHeader(alert);
                      break;

            case IPPROTO_ICMP:
                      PrintICMPHeader(alert);
                      break;

            default: break;
         }
      }

      fputc('\n', alert);

      fflush(alert);
      fclose(alert);
   }
   else
   {
      if(current->message != NULL)
      {
         if(net.proto == IPPROTO_ICMP)
	 {
            syslog(LOG_AUTHPRIV|LOG_WARNING, "[**] %s [**] %s -> %s", current->message, pip.saddr, pip.daddr);
	 }
	 else
	 {
            syslog(LOG_AUTHPRIV|LOG_WARNING, "[**] %s [**] %s:%i -> %s:%i", current->message, pip.saddr, pip.sport, pip.daddr, pip.dport);
	 }
      }
      else
      {
            syslog(LOG_AUTHPRIV|LOG_WARNING, "[**] No alert information! [**] %s -> %s", current->message, pip.saddr, pip.daddr);
      }

   }

   LogPkt();
}



/****************************************************************************
 *
 * Function: LogPkt()
 *
 * Purpose: Log packets that match one of the Snort rules, plus the rules
 *          message 
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void LogPkt()
{
   OpenLogFile(0);

   if(current->message != NULL)
      fprintf(log_ptr, "[**] %s [**]\n", current->message);

   PrintIPPkt(log_ptr, net.proto);

   fflush(log_ptr);

   fclose(log_ptr);
}




/****************************************************************************
 *
 * Function: PrintEthHeader(FILE *)
 *
 * Purpose: Print the packet Ethernet header to the specified stream
 *
 * Arguments: fp => file stream to print to 
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintEthHeader(FILE *fp)
{
   /* src addr */
   fprintf(fp, "%X:%X:%X:%X:%X:%X -> ", pip.eth_src[0],
           pip.eth_src[1], pip.eth_src[2], pip.eth_src[3],
           pip.eth_src[4], pip.eth_src[5]);

   /* dest addr */
   fprintf(fp, "%X:%X:%X:%X:%X:%X ", pip.eth_dst[0],
           pip.eth_dst[1], pip.eth_dst[2], pip.eth_dst[3],
           pip.eth_dst[4], pip.eth_dst[5]);

   /* protocol and pkt size */
   fprintf(fp, "type:0x%X len:0x%X\n", pip.eth_type, pip.eth_len);
}



/****************************************************************************
 *
 * Function: PrintIPHeader(FILE *)
 *
 * Purpose: Dump the IP header info to the specified stream
 *
 * Arguments: fp => stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintIPHeader(FILE *fp)
{
   /* if it's not ICMP or a fragment... */
   if((net.proto != IPPROTO_ICMP) || (!(pip.frag_off||pip.ip_mf)))
   {
      /* print the header complete with port information */
      fprintf(fp, "%s:%d -> %s:%d ", pip.saddr, pip.sport, pip.daddr, 
              pip.dport);
   }
   else
   {
      /* just print the straight IP header */
      fprintf(fp, "%s -> %s ", pip.saddr, pip.daddr);
   }

   if(!pv.showeth_flag)
   {
      fputc('\n', fp);
   } 

   fprintf(fp, "%s TTL:%d TOS:0x%X", pip.proto, pip.ttl, pip.tos);

   /* printf more frags/don't frag bits */
   if(pip.ip_df)
      fprintf(fp, " DF");

   if(pip.ip_mf)
      fprintf(fp, " MF");

   fputc('\n', fp);

   /* print IP options */
   if(pip.IPO_flag)
   {
      fwrite(pip.IPO_Str, 1, strlen(pip.IPO_Str), fp);
      fputc('\n', fp);
   }

   /* print fragment info if necessary */
   if(pip.frag_off || pip.ip_mf)
   {
      fprintf(fp, "FragID: 0x%X   FragOff: 0x%X", pip.frag_id, 
              (pip.frag_off&0xFFFF));
      fputc('\n', fp);
   }
} 



/****************************************************************************
 *
 * Function: PrintTCPHeader(FILE *)
 *
 * Purpose: Dump the TCP header info to the specified stream
 *
 * Arguments: fp => file stream to print data to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintTCPHeader(FILE *fp)
{
   /* print TCP flags */
   if(pip.flags & TH_SYN) fprintf(fp, "S"); else fprintf(fp, "*");
   if(pip.flags & TH_FIN) fprintf(fp, "F"); else fprintf(fp, "*");
   if(pip.flags & TH_RST) fprintf(fp, "R"); else fprintf(fp, "*");
   if(pip.flags & TH_PUSH) fprintf(fp, "P"); else fprintf(fp, "*");
   if(pip.flags & TH_ACK) fprintf(fp, "A"); else fprintf(fp, "*");
   if(pip.flags & TH_URG) fprintf(fp, "U"); else fprintf(fp, "*");

   /* print other TCP info */
   fprintf(fp, " Seq: 0x%lX   Ack: 0x%lX   Win: 0x%lX\n",pip.seq,
           pip.ack, pip.win);

   /* dump the TCP options */
   if(pip.TO_flag)
   {
      fwrite(pip.TO_Str, 1, strlen(pip.TO_Str), fp);
      fputc('\n', fp);
   }
}


/****************************************************************************
 *
 * Function: PrintUDPHeader(FILE *)
 *
 * Purpose: Dump the UDP header to the specified file stream
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintUDPHeader(FILE *fp)
{
   /* not much to do here... */
   fprintf(fp, "Len: %d\n", pip.udp_len);
}



/****************************************************************************
 *
 * Function: PrintICMPHeader(FILE *)
 *
 * Purpose: Print ICMP header
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintICMPHeader(FILE *fp)
{
   /* ... */
   fprintf(fp, "ID:%d   Seq:%d  %s\n", pip.icmp_id, pip.icmp_seqno,
           pip.icmp_str);
}
 
