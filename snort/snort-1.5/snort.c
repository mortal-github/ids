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
 * Purpose: Check out the README file for info on what you can do
 *          with Snort.
 *
 * Author: Martin Roesch (roesch@clark.net)
 *
 * Last Modified: 12/8/99
 *
 * Comments: Ideas and code stolen liberally from Mike Borella's IP Grab 
 *           program. Check out his stuff at http://www.borella.net.  I
 *           also have ripped some util functions from TCPdump, plus Mike's
 *           prog is derived from it as well.  All hail TCPdump....
 *
 * HP-UX 10.x note from Chris Sylvain:
 * if you run snort and receive the error message
 *  "ERROR: OpenPcap() device lan0 open:
 *                    recv_ack: promisc_phys: Invalid argument"
 * it's because there's another program running using the DLPI service.
 * The HP-UX implementation doesn't allow more than one libpcap program
 * at a time to run, unlike Linux.
 *
 ******************************************************************************/

/*  I N C L U D E S  **********************************************************/
#include "snort.h"


/****************************************************************************
 *
 * Function: main(int, char *)
 *
 * Purpose:  Handle program entry and exit, call main prog sections
 *
 * Arguments: See command line args in README file
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

   InitNetmasks();
   InitProtoNames();

/*
   InitPreprocessors();
   DumpPreprocessors();

   InitPlugIns();
   DumpPlugIns();
*/

   /* initialize the packet counter to loop forever */
   pv.pkt_cnt = -1;

   /* set the default alert mode */
   pv.alert_mode = ALERT_FULL;

   /* set the timezone (ripped from tcpdump) */
   thiszone = gmt2local(0);

   /* chew up the command line */
   ParseCmdLine(argc, argv);

   if(!pv.log_flag)
   {
      strncpy(pv.log_dir,DEFAULT_LOG_DIR,strlen(DEFAULT_LOG_DIR)+1);  
   }

   if(pv.use_rules || pv.log_flag)
   {
      /* perform some sanity checks on the output directory, etc*/
      SanityChecks();
   }
   
   if(!pv.logbin_flag)
   {
      if(!pv.nolog_flag)
         LogFunc = LogPkt;
      else
         LogFunc = NoLog;
   }

   if(pv.use_rules && pv.rules_order_flag)
   {
      printf("Rule application order changed to Pass->Alert->Log\n");
   }

   if(!pv.use_rules && !pv.verbose_flag && !pv.log_flag)
   {
      printf("\n\nUh, you need to tell me to do something....\n\n");
      ShowUsage(progname);
      exit(0);
   }

   if(pv.syslog_flag)
   {
      AlertFunc = SyslogAlert;
   }
   else if(pv.smbmsg_flag)
   {
#ifdef ENABLE_SMB_ALERTS
      AlertFunc = SmbAlert;
#else
      fprintf(stderr, "ERROR: SMB support not compiled into program, exiting...\n");
      exit(1);
#endif
   }
   else
   {
      switch(pv.alert_mode)
      {
         case ALERT_FAST:
            AlertFunc = FastAlert;
            OpenAlertFile();
 
            break;

         case ALERT_FULL:
            AlertFunc = FullAlert;
       
            break;

         case ALERT_NONE:
            AlertFunc = NoAlert;

            break;

         case ALERT_UNSOCK:
            AlertFunc = UnixSockAlert;
            OpenAlertSock();

            break;
      }
   }

   /* Tell 'em who wrote it, and what "it" is */
   DisplayBanner();

   /* if daemon mode requested, fork daemon first, otherwise
    * on linux interface will be reset.
    */
   if(pv.daemon_flag)
   {
#ifdef DEBUG
      printf("Entering daemon mode\n");
#endif
      GoDaemon();
   }
#ifdef DEBUG
   printf("Opening interface: %s\n", pv.interface);
#endif

   if(!pv.readmode_flag)
   {
      /* open up our libpcap packet capture interface */
      OpenPcap(pv.interface);
   }
   else
   {
      OpenPcap(pv.readfile);
   }

   if(pv.logbin_flag)
   {
#ifdef DEBUG
      printf("Initializing output file\n");
#endif
      InitLogFile();

      LogFunc = LogBin;
   }

#ifdef DEBUG
   printf("Setting Packet Processor\n");
#endif

   /* set the packet processor (ethernet, slip or raw)*/
   SetPktProcessor();


#ifdef DEBUG
   printf("Entering pcap loop\n");
#endif
   /* Read all packets on the device.  Continue until cnt packets read */
   if(pcap_loop(pd, pv.pkt_cnt, grinder, NULL) < 0)
   {
      if(pv.daemon_flag)
         syslog(LOG_CONS|LOG_DAEMON,"pcap_loop: %s", pcap_geterr(pd));
      else
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
   puts("Options:");
   puts("        -A         Set alert mode: fast, full, or none "
        " (alert file alerts only)"
        "\n                  \"unsock\" enables UNIX socket logging (experimental).");
   puts("        -a         Display ARP packets");
   puts("        -b         Log packets in tcpdump format (much faster!)");
   puts("        -c <rules> Use Rules File <rules>");
   puts("        -d         Dump the Application Layer");
   puts("        -D         Run Snort in background (daemon) mode");
   puts("        -e         Display the packet Ethernet addresses");
   puts("        -F <bpf>   Read BPF filters from file <bpf>");
   puts("        -h <hn>    Home network = <hn>");
   puts("        -i <if>    Listen on interface <if>");
   puts("        -l <ld>    Log to directory <ld>");
   puts("        -M <wrkst> Sends SMB message to workstations in file <wrkst>");
   puts("                   (Requires smbclient to be in PATH)");
   puts("        -n <cnt>   Exit after receiving <cnt> packets");
   puts("        -N         Turn off logging (alerts still work)");
   puts("        -o         Change the rule testing order to Pass|Alert|Log");
   puts("        -p         Disable promiscuous mode sniffing");
   puts("        -r <tf>    Read and process tcpdump file <tf>");
   puts("        -s         Log alert messages to syslog");
   puts("        -S <n=v>   Set rules file variable n equal to value v");
   puts("        -v         Be verbose");
   puts("        -V         Show version number");
   puts("        -x         Display IPX packets");
   puts("        -?         Show this information");
   puts("<Filter Options> are standard BPF options, as seen in TCPDump");
   putc('\n', stdout);

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
   int ch;                      /* storage var for getopt info */
   extern char *optarg;          /* for getopt */
   extern int optind;            /* for getopt */
   int read_bpf = 0;
   char bpf_file[STD_BUF];
   char *eq_p;

#ifdef DEBUG
   printf("Parsing command line...\n");
#endif

   pv.promisc_flag = 1;

   /* loop through each command line var and process it */
   while((ch = getopt(argc, argv, "S:pNA:F:DtM:br:xeh:l:dc:n:i:vV?aso")) != -1)
   {
#ifdef DEBUG
      printf("Processing cmd line switch: %c\n", ch);
#endif
      switch(ch)
      {
         case 'A': /* alert mode */
                 if(!strncasecmp(optarg,"none", 4))
                    pv.alert_mode = ALERT_NONE;

                 if(!strncasecmp(optarg,"full", 4))
                    pv.alert_mode = ALERT_FULL;

                 if(!strncasecmp(optarg,"fast", 4))
                    pv.alert_mode = ALERT_FAST;

                 if(!strncasecmp(optarg,"unsock", 4))
                    pv.alert_mode = ALERT_UNSOCK;
      
                 break;

         case 'D': /* daemon mode */
#ifdef DEBUG
                 printf("Daemon mode flag set\n");
#endif
                 pv.daemon_flag = 1;
                 break;

         case 'N': /* no logging mode */
#ifdef DEBUG
                 printf("Logging deactivated\n");
#endif
      
                 pv.nolog_flag = 1;

                 break;

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

         case 'b': /* log packets in binary format for post-processing */
#ifdef DEBUG
                 printf("Tcpdump logging mode active\n");
#endif

                 pv.logbin_flag = 1;

                 break;

         case 'F': /* read BPF filter in from a file */
#ifdef DEBUG
                 printf("Tcpdump logging mode active\n");
#endif
                 strncpy(bpf_file, optarg, STD_BUF - 1);

                 read_bpf = 1;

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
                 InitPreprocessors();
                 DumpPreprocessors();

                 InitPlugIns();
                 DumpPlugIns();
                 strncpy(pv.config_file, optarg, STD_BUF - 1);
                 pv.use_rules = 1;
                 ParseRulesFile(pv.config_file, 0);
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

         case 'p': /* disable explicit promiscuous mode */
		 pv.promisc_flag = 0;
#ifdef DEBUG
		 printf("Promiscuous mode disabled!\n");
#endif

		 break;

         case 'r': /* read packets from a TCPdump file instead of the net */
                 strncpy(pv.readfile, optarg, STD_BUF - 1);
                 pv.readmode_flag = 1;

                 break;

         case 's': /* log alerts to syslog */
		 pv.syslog_flag = 1;
#ifdef DEBUG
		 printf("Logging alerts to syslog\n");
#endif

		 break;

         case 'x': /* display IPX packets (decoder not implemented yet)*/
#ifdef DEBUG
                 printf("Show IPX active\n");
#endif
                 pv.showipx_flag = 1;
                                 
                 break;

         case 'M': /* SMB Message Option */

                 pv.smbmsg_flag = 1;
                 strncpy(pv.smbmsg_dir, optarg, STD_BUF-1);

                 break;

         case '?': /* show help and exit */
                 ShowUsage(progname);
                 exit(0);

         case 'V': /* prog ver already gets printed out, so we just exit */
                 exit(0);

         case 'h': /* set home network to x, this will help determine what to
                      set logging diectories to */

                 GenHomenet(optarg);

                 break;

         case 'S':
                 if((eq_p = strchr(optarg, '=')) != NULL) 
                 {
                    *eq_p = '\0';
                    VarDefine(optarg, eq_p + 1);
                 }
      }
   }

   if(read_bpf)
   {
      pv.pcap_cmd = read_infile(bpf_file);
   }
   else
   {
      /* set the BPF rules string (thanks Mike!) */
      pv.pcap_cmd = copy_argv(&argv[optind]);
   }

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
 * Function: GenHomenet(char *)
 *
 * Purpose: Translate the command line character string into its equivalent
 *          32-bit network byte ordered value (with netmask)
 *
 * Arguments: netdata => The address/CIDR block
 *
 * Returns: void function
 *
 ****************************************************************************/
void GenHomenet(char *netdata)
{
   struct in_addr net;           /* place to stick the local network data */
   char **toks;                  /* dbl ptr to store mSplit return data in */
   int num_toks;                 /* number of tokens mSplit returns */
   int nmask;                    /* temporary netmask storage */

   /* break out the CIDR notation from the IP address */
   toks = mSplit(optarg,"/",2,&num_toks,0);

   if(num_toks > 1)
   {
      /* convert the CIDR notation into a real live netmask */
      nmask = atoi(toks[1]);

      if((nmask > 0) && (nmask < 33))
      {
         pv.netmask = netmasks[nmask];
      }
      else
      {
         fprintf(stderr, "ERROR: Bad CIDR block [%s:%d], 1 to 32 please!\n",
                 toks[1],nmask);
         exit(1);
      }
   }
   else
   {
      fprintf(stderr, "ERROR: No netmask specified for home network!\n");
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
      printf("Net = %s (%X)\n", inet_ntoa(net), net.s_addr);
#endif
      /* set the final homenet address up */
      pv.homenet = ((u_long)net.s_addr & pv.netmask);
#ifdef DEBUG
      sin.s_addr = pv.homenet;
      printf("Homenet = %s (%X)\n", inet_ntoa(sin), sin.s_addr);
#endif
   }
 
   free(toks);
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
                if(!pv.readmode_flag)
                   printf("Decoding Ethernet on interface %s\n", pv.interface);
                else
                   printf("Entering readback mode....\n");

                grinder = (pcap_handler) DecodeEthPkt;
                break;

      case 13:
      case DLT_IEEE802:
                if(!pv.readmode_flag)
                   printf("Decoding Token Ring on interface %s\n", pv.interface);
                else
                   printf("Entering readback mode...\n");

                grinder = (pcap_handler) DecodeTRPkt;

                break;

      case DLT_SLIP:
                if(!pv.readmode_flag)
                   printf("Decoding Slip on interface %s\n", pv.interface);
                else
                   printf("Entering readback mode....\n");

		if(pv.showeth_flag == 1)
	        {
		   printf("Disabling Ethernet header printout (you aren't using Ethernet!\n");
		   pv.showeth_flag = 0;
		}

                grinder = (pcap_handler) DecodeSlipPkt;

                break;

      case DLT_PPP:
                if(!pv.readmode_flag)
                   printf("Decoding PPP on interface %s\n", pv.interface);
                else
                   printf("Entering readback mode....\n");

               if(pv.showeth_flag == 1)
               {
               /* do we need ppp header showup? it's only 4 bytes anyway ;-) */
                  printf("Disabling Ethernet header printout (you aren't using Ethernet!\n");
                  pv.showeth_flag = 0;
               }

                grinder = (pcap_handler) DecodePppPkt;
               break;

      case DLT_NULL: /* loopback and stuff.. you wouldn't perform intrusion
                      * detection on it, but it's ok for testing.
                      */
               if(!pv.readmode_flag)
                  printf("Decoding LoopBack on interface %s\n", pv.interface);
               else
                  printf("Entering readback mode....\n");

               if(pv.showeth_flag == 1)
               {
                  printf("Disabling Ethernet header printout (you aren't using Ethernet!\n");
                  pv.showeth_flag = 0;
               }

               grinder = (pcap_handler) DecodeNullPkt;

               break;




#ifdef DLT_RAW /* Not supported in some arch or older pcap versions */
      case DLT_RAW:
                if(!pv.readmode_flag)
                   printf("Decoding raw data on interface %s\n", pv.interface);
                else
                   printf("Entering readback mode....\n");

		if(pv.showeth_flag == 1)
	        {
		   printf("Disabling Ethernet header printout (you aren't using Ethernet!\n");
		   pv.showeth_flag = 0;
		}

                grinder = (pcap_handler) DecodeRawPkt;

                break;
#endif

#ifdef DLT_I4L_RAWIP
      case DLT_I4L_RAWIP:
                printf("Decoding I4L-rawip on interface %s\n", pv.interface);
                grinder = (pcap_handler) DecodeI4LRawIPPkt;
                break;
#endif

#ifdef DLT_I4L_IP
      case DLT_I4L_IP:
                printf("Decoding I4L-ip on interface %s\n", pv.interface);
                grinder = (pcap_handler) DecodeEthPkt;
                break;
#endif

#ifdef DLT_I4L_CISCOHDLC
      case DLT_I4L_CISCOHDLC:
                printf("Decoding I4L-cisco-h on interface %s\n", pv.interface);
                grinder = (pcap_handler) DecodeI4LCiscoIPPkt;
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

   if(pv.interface == NULL)
   {
#ifdef DEBUG
      printf("pv.interface is NULL, looking up interface....   ");
#endif
      /* look up the device and get the handle */
      pv.interface = pcap_lookupdev(errorbuf);
#ifdef DEBUG
      printf("found interface %s\n", pv.interface);
#endif 

      if(pv.interface == NULL)
      {
         if(pv.daemon_flag)
                syslog(LOG_CONS|LOG_DAEMON, 
               "ERROR: OpenPcap() interface lookup: \n\t%s\n", errorbuf);
         else 
         fprintf(stderr, "ERROR: OpenPcap() interface lookup: \n\t%s\n", 
                 errorbuf);
         exit(1);
      }
   }
 
   if(!pv.readmode_flag)
   {
      snaplen = SNAPLEN;
      /* get the device file descriptor */
      pd = pcap_open_live(pv.interface, snaplen,
                          pv.promisc_flag ? PROMISC : 0, READ_TIMEOUT, errorbuf);
   }
   else
   {
      pd = pcap_open_offline(intf, errorbuf);

      if(pd == NULL)
      {
         fprintf(stderr, "ERROR => unable to open file %s for readback: %s\n", 
                 intf, errorbuf);

         exit(1);
      }

      snaplen = pcap_snapshot(pd);
      printf("snaplen = %d\n", snaplen);
   }

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
      fprintf(stderr, "PCAP command: %s\n", pv.pcap_cmd);
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


   /* make sure everything that needs to go to the screen gets there */
   fflush(stdout);

   printf("\nExiting...\n");

   if(pv.logbin_flag)
   {
      fclose(binlog_ptr);
   }

   if(pv.smbmsg_flag)
   {
      unlink("/tmp/.snortmsg");
   }

   if(pv.alert_mode == ALERT_FAST)
   {
      fclose(alert);
   }

   if(pv.readmode_flag)
   {
      puts("\n\n===============================================================================");

      recv = pc.tcp+pc.udp+pc.icmp+pc.arp+pc.ipx+pc.other;

      printf("Snort processed %d packets.\n", (int) recv);

      puts("Breakdown by protocol:");
      printf("    TCP: %-10ld (%.3f%%)\n", pc.tcp, CalcPct((float)pc.tcp, recv));
      printf("    UDP: %-10ld (%.3f%%)\n", pc.udp, CalcPct((float)pc.udp, recv));
      printf("   ICMP: %-10ld (%.3f%%)\n", pc.icmp, CalcPct((float)pc.icmp, recv));
      printf("    ARP: %-10ld (%.3f%%)\n", pc.arp, CalcPct((float)pc.arp, recv));
      printf("    IPX: %-10ld (%.3f%%)\n", pc.ipx, CalcPct((float)pc.ipx, recv));
      printf("  OTHER: %-10ld (%.3f%%)\n", pc.other, CalcPct((float)pc.other, recv));
      puts("\n\n===============================================================================");
      exit(0);
   }

   if(pd == NULL)
      exit(1);

   /* collect the packet stats */
   if(pcap_stats(pd, &ps))
   {
      pcap_perror(pd, "pcap_stats");
   }
   else
   {
      recv = ps.ps_recv;
      drop = ps.ps_drop;

      puts("\n\n===============================================================================");
      printf("Snort received %d packets", ps.ps_recv);

      if(ps.ps_recv)
      {
#ifndef LINUX
         printf(" and dropped %d(%.3f%%) packets\n\n", ps.ps_drop, 
                CalcPct(drop, recv));
#else
         printf(".\nPacket loss statistics are unavailable under Linux.  Sorry!\n\n");
#endif
      }
      else
      {
         puts(".\n");
      }
      puts("Breakdown by protocol:");
      printf("    TCP: %-10ld (%.3f%%)\n", pc.tcp, CalcPct((float)pc.tcp, recv));
      printf("    UDP: %-10ld (%.3f%%)\n", pc.udp, CalcPct((float)pc.udp, recv));
      printf("   ICMP: %-10ld (%.3f%%)\n", pc.icmp, CalcPct((float)pc.icmp, recv));
      printf("    ARP: %-10ld (%.3f%%)\n", pc.arp, CalcPct((float)pc.arp, recv));
      printf("    IPX: %-10ld (%.3f%%)\n", pc.ipx, CalcPct((float)pc.ipx, recv));
      printf("  OTHER: %-10ld (%.3f%%)\n", pc.other, CalcPct((float)pc.other, recv));

      puts("===============================================================================");
   }


   pcap_close(pd);

   exit(0);
}



/****************************************************************************
 *
 * Function: CalcPct(float, float)
 *
 * Purpose:  Calculate the percentage of a value compared to a total
 *
 * Arguments: cnt => the numerator in the equation
 *            total => the denominator in the calculation
 *
 * Returns: pct -> the percentage of cnt to value
 *
 ****************************************************************************/
float CalcPct(float cnt, float total)
{
   float pct;

   if(cnt > 0.0)
      pct = cnt/total;
   else
      return 0.0;

   pct *= 100.0;

   return pct;
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
   printf("\n-*> Snort! <*-\nVersion %s\nBy Martin Roesch (roesch@clark.net, www.clark.net/~roesch)\n", VERSION);
   return 0;
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

   lt = localtime((time_t *)&tvp->tv_sec);

   s = (tvp->tv_sec + thiszone) % 86400;

   (void)sprintf(timebuf, "%02d/%02d-%02d:%02d:%02d.%06u ", lt->tm_mon+1, 
                 lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60, 
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




/****************************************************************************
 *
 * Function: InitNetMasks()
 *
 * Purpose: Loads the netmask struct in network order.  Yes, I know I could
 *          just load the array when I define it, but this is what occurred
 *          to me when I wrote this at 3:00 AM.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void InitNetmasks()
{
   netmasks[0] = 0x0;
   netmasks[1] = 0x80000000;
   netmasks[2] = 0xC0000000;
   netmasks[3] = 0xE0000000;
   netmasks[4] = 0xF0000000;
   netmasks[5] = 0xF8000000;
   netmasks[6] = 0xFC000000;
   netmasks[7] = 0xFE000000;
   netmasks[8] = 0xFF000000;
   netmasks[9] = 0xFF800000;
   netmasks[10] = 0xFFC00000;
   netmasks[11] = 0xFFE00000;
   netmasks[12] = 0xFFF00000;
   netmasks[13] = 0xFFF80000;
   netmasks[14] = 0xFFFC0000;
   netmasks[15] = 0xFFFE0000;
   netmasks[16] = 0xFFFF0000;
   netmasks[17] = 0xFFFF8000;
   netmasks[18] = 0xFFFFC000;
   netmasks[19] = 0xFFFFE000;
   netmasks[20] = 0xFFFFF000;
   netmasks[21] = 0xFFFFF800;
   netmasks[22] = 0xFFFFFC00;
   netmasks[23] = 0xFFFFFE00;
   netmasks[24] = 0xFFFFFF00;
   netmasks[25] = 0xFFFFFF80;
   netmasks[26] = 0xFFFFFFC0;
   netmasks[27] = 0xFFFFFFE0;
   netmasks[28] = 0xFFFFFFF0;
   netmasks[29] = 0xFFFFFFF8;
   netmasks[30] = 0xFFFFFFFC;
   netmasks[31] = 0xFFFFFFFE;
   netmasks[32] = 0xFFFFFFFF;
}




/****************************************************************************
 *
 * Function: GoDaemon()
 *
 * Purpose: Puts the program into daemon mode, nice and quiet like....
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void GoDaemon(void) 
{
   int fs;

   printf("Initializing daemon mode\n");

   if(getppid() != 1) 
   {
      fs=fork();

      if(fs > 0) 
         exit(0); /* parent */

      if(fs < 0)
      {
         perror("fork");
         exit(1);
      }

      setsid();
   }

   /* redirect stdin/stdout/stderr to /dev/null */
   close(0);
   close(1);
   close(2);

#ifdef DEBUG
   open("/tmp/snort.debug", O_CREAT|O_RDWR);
#else
   open("/dev/null",O_RDWR);
#endif

   dup(0);
   dup(0);
   umask(0);

   return;
}






/****************************************************************************
 *
 * Function: SanityChecks()
 *
 * Purpose: CyberPsychotic sez: basically we only check if logdir exist and 
 *          writable, since it might screw the whole thing in the middle. Any
 *          other checks could be performed here as well.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/

void SanityChecks(void)
{
   struct stat st;

   stat(pv.log_dir,&st);

   if(!S_ISDIR(st.st_mode) || access(pv.log_dir,W_OK) == -1) 
   {
      fprintf(stderr,"\n*Error* :"
              "Can not get write to logging directory %s.\n"
              "(directory doesn't "
              "exist or permissions are set incorrectly)\n\n",
              pv.log_dir);
      exit(0);
   }
}



/****************************************************************************
 *
 * Function: read_infile(char *)
 *
 * Purpose: Reads the BPF filters in from a file.  Ripped from tcpdump.
 *
 * Arguments: fname => the name of the file containing the BPF filters
 *
 * Returns: the processed BPF string
 *
 ****************************************************************************/
char *read_infile(char *fname)
{
   register int fd, cc;
   register char *cp;
   struct stat buf;

   fd = open(fname, O_RDONLY);

   if(fd < 0)
      fprintf(stderr, "can't open %s: %s", fname, pcap_strerror(errno));

   if(fstat(fd, &buf) < 0)
      fprintf(stderr, "can't stat %s: %s", fname, pcap_strerror(errno));

   cp = malloc((u_int)buf.st_size + 1);

   cc = read(fd, cp, (int)buf.st_size);

   if(cc < 0)
     fprintf(stderr, "read %s: %s", fname, pcap_strerror(errno));

   if(cc != buf.st_size)
      fprintf(stderr, "short read %s (%d != %d)", fname, cc, (int)buf.st_size);

   cp[(int)buf.st_size] = '\0';

   return (cp);
}



/****************************************************************************
 *
 * Function: InitProtoNames()
 *
 * Purpose: Initializes the protocol names
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void InitProtoNames()
{
   strncpy(protocol_names[IPPROTO_ICMP], "ICMP", 5);
   strncpy(protocol_names[IPPROTO_TCP], "TCP", 4);
   strncpy(protocol_names[IPPROTO_UDP], "UDP", 4);
}
