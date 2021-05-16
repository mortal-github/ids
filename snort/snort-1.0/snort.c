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

/******************************************************************************
 *
 * Program: Snort
 *
 * Purpose: This is a fairly generic sniffing program which does some nice
 *          logging.  You can tell it what the "home" network is and it will
 *          log all traffic in terms of the remote side of the connection.
 *          The program can take BPF-style filtering commands at the command
 *          line and filter out the packets it receives to just the network
 *          of interest.  It can also do rule based logging based upon packet
 *          headers or application layer content.
 *
 * Author: Martin Roesch (roesch@clark.net)
 *
 * Last Modified: 4/8/98
 *
 * Comments: Ideas and code stolen liberally from Mike Borella's IP Grab 
 *           program. Check out his stuff at http://www.borella.net.  I
 *           also have ripped some util functions from TCPdump, plus Mike's
 *           prog is derived from it as well.  All hail TCPdump....
 *
 ******************************************************************************/

/*  I N C L U D E S  **********************************************************/
#include "snort.h"


PrintIP pip;  /* print out data struct */



/****************************************************************************
 *
 * Function: main(int, char *)
 *
 * Purpose:  Handle program entry and exit, call main prog sections
 *
 * Arguments: -d => dump the application layer data
 *            -c => use configuration file
 *            -a => display ARP packets
 *            -n => exit after receiving x packets
 *            -i => listen on interface x
 *            -l => log to directory x
 *            -h => set "home" network to x
 *            -v => be verbose
 *            -V => show the version number and exit
 *            -? => show the program help data and exit
 *            list => a list of BPF commands can also be sent to the program
 *                    to control what data gets captured
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 ****************************************************************************/
int main(int argc, char *argv[])
{
   /* make this prog behave nicely when signals come along */
   signal(SIGKILL, CleanExit);
   signal(SIGTERM, CleanExit);
   signal(SIGINT, CleanExit);
   signal(SIGQUIT, CleanExit);
   signal(SIGHUP, CleanExit);

   /* set a global ptr to the program name so other functions can tell
      what the program name is */
   progname = argv[0];

   /* Tell 'em who wrote it, and what "it" is */
   DisplayBanner();

   /* initialize the packet counter to loop forever */
   pv.pkt_cnt = -1;

   /* set the timezone (ripped from tcpdump) */
   thiszone = gmt2local(0);

   /* chew up the command line */
   ParseCmdLine(argc, argv);

   if(!pv.log_flag)
      strncpy(pv.log_dir, ".", 1);

   if(pv.use_rules && pv.rules_order_flag)
   {
      printf("Rule application order changed to Pass->Alert->Log\n");
   }

   if(!pv.use_rules && !pv.verbose_flag)
   {
      printf("\n\nUh, you need to tell me to do something....\n\n");
      ShowUsage(progname);
      exit(0);
   }

   /* open up our libpcap packet capture interface */
   OpenPcap(pv.interface);

   /* set the packet processor (ethernet, slip or raw)*/
   SetPktProcessor();

  /* Read all packets on the device.  Continue until cnt packets read */
  if(pcap_loop(pd, pv.pkt_cnt, grinder, NULL) < 0)
  {
     fprintf(stderr, "pcap_loop: %s", pcap_geterr(pd));
     CleanExit();
  }

  /* close the capture interface */
  pcap_close(pd);

  return 0;
}



/****************************************************************************
 *
 * Function: ShowUsage(char *)
 *
 * Purpose:  Display the program options and exit
 *
 * Arguments: progname => name of the program (argv[0])
 *
 * Returns: 0 => success
 *
 ****************************************************************************/
int ShowUsage(char *progname)
{
   printf("\nUSAGE: %s [-options] <filter options>\n", progname);
   printf("Options:\n");
   printf("         -a         Display ARP packets\n");
   printf("         -c <conf>  Use Configuration File <conf>\n");
   printf("         -d         Dump the Application Layer\n");
   printf("         -e         Display the packet Ethernet addresses\n");
   printf("         -h <hn>    Home network = <hn>\n");
   printf("         -i <if>    Listen on interface <if>\n");
   printf("         -l <ld>    Log to directory <ld>\n");
   printf("         -n <cnt>   Exit after receiving <cnt> packets\n");
   printf("         -o         Change the rule application order to Pass|Alert|Log\n");
   printf("         -s         Log alert messages to syslog\n");
   printf("         -v         Be verbose\n");
   printf("         -V         Show version number\n");
   printf("         -?         Show this information\n");
   printf("<Filter Options> are standard BPF options, as seen in TCPDump\n");
   printf("\n");

   fflush(stdout);

   return 0;
}




/****************************************************************************
 *
 * Function: ParseCmdLine(int, char *)
 *
 * Purpose:  Parse command line args
 *
 * Arguments: argc => count of arguments passed to the routine
 *            argv => 2-D character array, contains list of command line args
 *
 * Returns: 0 => success, 1 => exit on error
 *
 ****************************************************************************/
int ParseCmdLine(int argc, char *argv[])
{
   char ch;                      /* storage var for getopt info */
   extern char *optarg;          /* for getopt */
   extern int optind;            /* for getopt */
   struct in_addr net;           /* place to stick the local network data */
   char **toks;                  /* dbl ptr to store mSplit return data in */
   int num_toks;                 /* number of tokens mSplit returns */
   int nmask;                    /* temporary netmask storage */

#ifdef DEBUG
   printf("Parsing command line...\n");
#endif

   /* loop through each command line var and process it */
   while((ch = getopt(argc, argv, "eh:l:dc:n:i:vV?aso")) != EOF)
   {
#ifdef DEBUG
      printf("Processing cmd line switch: %c\n", ch);
#endif
      switch(ch)
      {
         case 'l': /* use log dir <X> */
                 strncpy(pv.log_dir, optarg, STD_BUF-1);
#ifdef DEBUG
                 printf("Log directory = %s\n", pv.log_dir);
#endif
                 pv.log_flag = 1;
                 break;
                              
         case 'e': /* show Ethernet Header info */
#ifdef DEBUG
                 printf("Show ETH active\n");
#endif
                 pv.showeth_flag = 1;
                 
                 break;

         case 'a': /* show ARP packets */
#ifdef DEBUG
                 printf("Show ARP active\n");
#endif
                 pv.showarp_flag = 1;
                 
                 break;

         case 'd': /* dump the application layer data */
                 pv.data_flag = 1;
#ifdef DEBUG
                 printf("Data Flag active\n");
#endif
                 break;

         case 'v': /* be verbose */
                 pv.verbose_flag = 1;
#ifdef DEBUG
                 printf("Verbose Flag active\n");
#endif
                 break;

         case 'n': /* grab x packets and exit */
                 pv.pkt_cnt = atoi(optarg);
#ifdef DEBUG
                 printf("Exiting after %d packets\n", pv.pkt_cnt);
#endif
                 break;

         case 'c': /* use configuration file x ( which currently isn't used) */
                 strncpy(pv.config_file, optarg, STD_BUF - 1);
                 pv.use_rules = 1;
                 ParseRulesFile(pv.config_file);
#ifdef DEBUG
                 printf("Config file = %s\n", pv.config_file);
#endif
                 break;

         case 'i': /* listen on interface x */
                 pv.interface = (char *) malloc(strlen(optarg) + 1);
                 bzero(pv.interface, strlen(optarg)+1);
                 strncpy(pv.interface, optarg, strlen(optarg));
#ifdef DEBUG
                 printf("Interface = %s\n", pv.interface);
#endif
                 break;

         case 'o': /* change the rules processing order to passlist first */
		 pv.rules_order_flag = 1;
#ifdef DEBUG
		 printf("Rule application order changed to Pass->Alert->Log\n");
#endif

		 break;

         case 's': /* log alerts to syslog */
		 pv.syslog_flag = 1;
#ifdef DEBUG
		 printf("Logging alerts to syslog\n");
#endif

		 break;

         case '?': /* show help and exit */
                 ShowUsage(progname);
                 exit(0);

         case 'V': /* prog ver already gets printed out, so we just exit */
                 exit(0);

         case 'h': /* set home network to x, this will help determine what to
                      set logging diectories to */

                 /* break out the CIDER notation from the IP address */
                 toks = mSplit(optarg,"/",2,&num_toks,0);

                 if(num_toks > 1)
                 {
                    /* remove the <CR/LF> */
                    /*strip(toks[1]);*/

                    /* convert the CIDER notation into a real live netmask */
                    nmask = 32 - atoi(toks[1]);

                    if(nmask < 25)
                    {
                       pv.netmask = pow(2, nmask) - 1;
                       pv.netmask = -pv.netmask;
                       pv.netmask -= 1;
                    }
                    else
                    {
                       /* class A and down only, we're not doing the whole Net */
                       fprintf(stderr, "Bad CIDER block [%s:%d], 8 to 32 please!\n",toks[1],nmask);
                       exit(1);
                    }
                 }
                 else
                 {
                    fprintf(stderr, "You need to specify a netmask with that home net address!\n");
                    exit(1);
                 }

                 /* since PC's store things the "wrong" way, shuffle the bytes into 
                    the right order */
#ifndef WORDS_BIGENDIAN
                 pv.netmask = htonl(pv.netmask);
#endif

#ifdef DEBUG
                 printf("homenet netmask = %#8lX\n", pv.netmask);
#endif
                 /* convert the IP addr into its 32-bit value */
                 if((net.s_addr = inet_addr(toks[0])) ==-1)
                 {
                    fprintf(stderr, "ERROR: Homenet (%s) didn't x-late, WTF?\n",
                            toks[0]);
                    exit(0);
                 }
                 else
                 {
#ifdef DEBUG
                    struct in_addr sin;
                    printf("Net = %s (%lX)\n", inet_ntoa(net), net.s_addr);
#endif
                    /* set the final homenet address up */
                    pv.homenet = ((u_long)net.s_addr & pv.netmask);
#ifdef DEBUG
                    sin.s_addr = pv.homenet;
                    printf("Homenet = %s (%lX)\n", inet_ntoa(sin), sin.s_addr);
#endif
                 }
 
                 free(toks);

                 break;
      }
   }

   /* set the BPF rules string (thanks Mike!) */
   pv.pcap_cmd = copy_argv(&argv[optind]);

#ifdef DEBUG
   if(pv.pcap_cmd != NULL)
   {
      printf("pcap_cmd = %s\n", pv.pcap_cmd);
   }
   else
   {
      printf("pcap_cmd is NULL!\n");
   }
#endif

   return 0;
}


/****************************************************************************
 *
 * Function: SetPktProcessor()
 *
 * Purpose:  Set which packet processing function we're going to use based on 
 *           what type of datalink layer we're using
 *
 * Arguments: None.
 *
 * Returns: 0 => success
 *
 ****************************************************************************/
int SetPktProcessor()
{
   switch(datalink)
   {
      case DLT_EN10MB:
                printf("Decoding Ethernet on interface %s\n", pv.interface);
                grinder = (pcap_handler) DecodeEthPkt;
                break;

      case DLT_SLIP:
                printf("Decoding Slip on interface %s\n", pv.interface);

		if(pv.showeth_flag == 1)
	        {
		   printf("Disabling Ethernet header printout (you aren't using Ethernet!\n");
		   pv.showeth_flag = 0;
		}

                grinder = (pcap_handler) DecodeSlipPkt;

                break;

#ifdef DLT_RAW /* Not supported in some arch or older pcap versions */
      case DLT_RAW:
                printf("Decoding raw data on interface %s\n", pv.interface);

		if(pv.showeth_flag == 1)
	        {
		   printf("Disabling Ethernet header printout (you aren't using Ethernet!\n");
		   pv.showeth_flag = 0;
		}

                grinder = (pcap_handler) DecodeRawPkt;

                break;
#endif

       default:
                fprintf(stderr, "\n%s cannot handle data link type %d", 
                        progname, datalink);
                CleanExit();
    }
 
   return 0;
}
   

/****************************************************************************
 *
 * Function: OpenPcap(char *)
 *
 * Purpose:  Open the libpcap interface
 *
 * Arguments: intf => name of the interface to open 
 *
 * Returns: 0 => success, exits on problems
 *
 ****************************************************************************/
int OpenPcap(char *intf)
{
   bpf_u_int32 localnet, netmask;    /* net addr holders */
   struct bpf_program fcode;         /* Finite state machine holder */
   char errorbuf[PCAP_ERRBUF_SIZE];  /* buffer to put error strings in */
 
   /* look up the device and get the handle */
   if(pv.interface == NULL)
   {
      pv.interface = pcap_lookupdev(errorbuf);

      if(pv.interface == NULL)
      {
         fprintf(stderr, "ERROR: OpenPcap() device %s lookup: \n\t%s\n", 
                 pv.interface, errorbuf);
         exit(1);
      }
   }
 
   /* get the device file descriptor */
   pd = pcap_open_live(pv.interface, SNAPLEN, PROMISC, READ_TIMEOUT, errorbuf);

   if (pd == NULL) 
   {
      fprintf(stderr, "ERROR: OpenPcap() device %s open: \n\t%s\n", 
              pv.interface, errorbuf);
      exit(1);
   }
 
   /* get local net and netmask */
   if(pcap_lookupnet(pv.interface, &localnet, &netmask, errorbuf) < 0)
   {
      fprintf(stderr, "ERROR: OpenPcap() device %s network lookup: \n\t%s\n", 
              pv.interface, errorbuf);
      exit(1);
   }
  
   /* compile command line filter spec info fcode FSM */
   if(pcap_compile(pd, &fcode, pv.pcap_cmd, 0, netmask) < 0)
   {
      fprintf(stderr, "ERROR: OpenPcap() FSM compilation failed: \n\t%s\n", 
              pcap_geterr(pd));
      exit(1);
   } 
  
   /* set the pcap filter */
   if(pcap_setfilter(pd, &fcode) < 0)
   {
      fprintf(stderr, "ERROR: OpenPcap() setfilter: \n\t%s\n", pcap_geterr(pd));
      exit(1);
   }
 
   /* get data link type */
   datalink = pcap_datalink(pd);

   if (datalink < 0) 
   {
      fprintf(stderr, "ERROR: OpenPcap() datalink grab: \n\t%s\n", pcap_geterr(pd));
      exit(1);
   }

   return 0;
}
 
/****************************************************************************
 *
 * Function: CleanExit()
 *
 * Purpose:  Clean up misc file handles and such and exit
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void CleanExit()
{
   struct pcap_stat ps;
   float drop;
   float recv;
#ifndef LINUX
   float pct;
#endif

   /* make sure everything that needs to go to the screen gets there */
   fflush(stdout);

   /* collect the packet stats */
   if(pcap_stats(pd, &ps))
   {
      pcap_perror(pd, "pcap_stats");
   }
   else
   {
      recv = ps.ps_recv;
      drop = ps.ps_drop;

      printf("\n\nSnort received %d packets\n", ps.ps_recv);

      if(ps.ps_recv)
      {
#ifndef LINUX
         pct = drop/recv;
         pct *= 100.0;
         printf("Snort dropped %d(%f%%) packets!\n", ps.ps_drop, pct);
#else
         printf("Using Linux => no packet loss statistics!\n");
#endif
      }
   }

   printf("Exiting...\n");

   pcap_close(pd);

   exit(0);
}


/****************************************************************************
 *
 * Function: DisplayBanner()
 *
 * Purpose:  Show valuable proggie info
 *
 * Arguments: None.
 *
 * Returns: 0 all the time
 *
 ****************************************************************************/
int DisplayBanner()
{
   printf("\n-*> Snort! <*-\nVersion %s, By Martin Roesch (roesch@clark.net)\n", VERSION);
   return 0;
}



/****************************************************************************
 *
 * Function: GetTime(char *)
 *
 * Purpose: Generate a time stamp and stuff it in a buffer
 *
 * Arguments: timebuf => buffer to stuff timestamp into
 *
 * Returns: void function
 *
 ****************************************************************************/
void GetTime(char *timebuf)
{
   time_t curr_time;      /* place to stick the clock data */
   struct tm *loc_time;   /* place to stick the adjusted clock data */

   curr_time = time(NULL);
   loc_time = localtime(&curr_time);

   strftime(timebuf,STD_BUF-1,"%m/%d/%y[%H.%M.%S]",loc_time);

   return;
}



/****************************************************************************
 *  
 * Function: ts_print(register const struct, char *)
 * 
 * Purpose: Generate a time stamp and stuff it in a buffer.  This one has
 *          millisecond precision.  Oh yeah, I ripped this code off from
 *          TCPdump, props to those guys.
 * 
 * Arguments: timeval => clock struct coming out of libpcap
 *            timebuf => buffer to stuff timestamp into
 *      
 * Returns: void function
 * 
 ****************************************************************************/
void ts_print(register const struct timeval *tvp, char *timebuf)
{               
   register int s;  
   struct tm *lt;   /* place to stick the adjusted clock data */

   lt = localtime(&tvp->tv_sec);

   s = (tvp->tv_sec + thiszone) % 86400;

   (void)sprintf(timebuf, "%02d%02d%02d-%02d:%02d:%02d.%06u", lt->tm_mon+1, 
                 lt->tm_mday, lt->tm_year, s / 3600, (s % 3600) / 60, s % 60, 
                 (u_int)tvp->tv_usec);
}



/****************************************************************************
 *  
 * Function: gmt2local(time_t)
 * 
 * Purpose: Figures out how to adjust the current clock reading based on the
 *          timezone you're in.  Ripped off from TCPdump.
 * 
 * Arguments: time_t => offset from GMT
 *      
 * Returns: offset seconds from GMT
 * 
 ****************************************************************************/
int gmt2local(time_t t)
{
   register int dt, dir;
   register struct tm *gmt, *loc;
   struct tm sgmt;
 
   if(t == 0)
      t = time(NULL);

   gmt = &sgmt;
   *gmt = *gmtime(&t);
   loc = localtime(&t);

   dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 + 
        (loc->tm_min - gmt->tm_min) * 60;

   /* If the year or julian day is different, we span 00:00 GMT
     and must add or subtract a day. Check the year first to
     avoid problems when the julian day wraps. */

   dir = loc->tm_year - gmt->tm_year;

   if(dir == 0)
      dir = loc->tm_yday - gmt->tm_yday;

   dt += dir * 24 * 60 * 60;

   return (dt);
}




/****************************************************************************
 *
 * Function: copy_argv(u_char **)
 *
 * Purpose: Copies a 2D array (like argv) into a flat string.  Stolen from
 *          TCPDump.
 *
 * Arguments: argv => 2D array to flatten
 *
 * Returns: Pointer to the flat string
 *
 ****************************************************************************/
char *copy_argv(char **argv)
{
  char **p;
  u_int len = 0;
  char *buf;
  char *src, *dst;
  void ftlerr(char *, ...);

  p = argv;
  if (*p == 0) return 0;

  while (*p)
    len += strlen(*p++) + 1;

  buf = (char *) malloc (len);
  if(buf == NULL)
  {
     fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
     exit(0);
  }
  p = argv;
  dst = buf;
  while ((src = *p++) != NULL)
    {
      while ((*dst++ = *src++) != '\0');
      dst[-1] = ' ';
    }
  dst[-1] = '\0';

  return buf;
}




/****************************************************************************
 *
 * Function: strip(char *)
 *
 * Purpose: Strips a data buffer of CR/LF/TABs.  Replaces CR/LF's with
 *          NULL and TABs with spaces.
 *
 * Arguments: data => ptr to the data buf to be stripped
 *
 * Returns: size of the newly stripped string
 *
 ****************************************************************************/
int strip(char *data)
{
   int size;
   char *end;
   char *idx;

   idx = data;
   end = data + strlen(data);
   size = end - idx;

   while(idx != end)
   {
      if((*idx == '\n') ||
         (*idx == '\r'))
      {
         *idx = 0;
         size--;
      }

      if(*idx == '\t')
      {
         *idx = ' ';
      }

      idx++;
   }

   return size;
}

