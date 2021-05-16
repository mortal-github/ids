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

#include "decode.h"

extern PrintIP pip;

/****************************************************************************
 *
 * Function: DecodeEthPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeEthPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   int pkt_len;  /* suprisingly, the length of the packet */
   int cap_len;  /* caplen value */
   int pkt_type; /* type of pkt (ARP, IP, etc) */
   EtherHdr *eh; /* ethernet header pointer (thanks Mike!) */

   /* set the lengths we need */
   pkt_len = pkthdr->len;       /* total packet length */
   cap_len = pkthdr->caplen;    /* captured packet length */

   ClearDumpBuf();
   bzero((void *) &pip, sizeof(PrintIP));

#ifdef DEBUG
   printf("Packet!\n");
#endif

   bzero(&net, sizeof(NetData));

   ts_print(&pkthdr->ts, pip.timestamp);

   /* do a little validation */
   if(cap_len < ETHERNET_HEADER_LEN)
   {
      fprintf(stderr, "Ethernet header length < cap len! (%d bytes)\n",
              cap_len);
      return;
   }


   /* lay the ethernet structure over the packet data */
   eh = (EtherHdr *) pkt;

   /* grab out the network type */
   pkt_type = ntohs(eh->ether_type);

   if(pv.showeth_flag)
   {
      memcpy(pip.eth_src, eh->ether_src, 6);
      memcpy(pip.eth_dst, eh->ether_dst, 6);
      pip.eth_len = pkt_len;
      pip.eth_type = pkt_type;
   }


   /* set the packet index pointer */
   pktidx = pkt;

   /* increment the index pointer to the start of the network layer */
   pktidx += ETHERNET_HEADER_LEN;

   switch(pkt_type)
   {
      case ETHERNET_TYPE_IP:
#ifdef DEBUG
                      printf("IP Packet\n");
#endif
                      DecodeIP(pktidx, pkt_len-ETHERNET_HEADER_LEN);
                      return;

      case ETHERNET_TYPE_ARP:
      case ETHERNET_TYPE_REVARP:
                      if(pv.showarp_flag)
                         DecodeARP(pktidx, pkt_len-ETHERNET_HEADER_LEN, cap_len);
                      return;

      case ETHERNET_TYPE_IPX:
                      DecodeIPX(pktidx, (pkt_len-ETHERNET_HEADER_LEN));
                      return;

      default:
             return;
   }

   return;
}



/****************************************************************************
 *
 * Function: DecodeSlipPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: For future expansion
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeSlipPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   u_int len;
   u_int cap_len;

   len = pkthdr->len;
   cap_len = pkthdr->caplen;

   ClearDumpBuf();
   bzero((void *) &pip, sizeof(PrintIP));

#ifdef DEBUG
   printf("Packet!\n");
#endif

   bzero(&net, sizeof(NetData));

   ts_print(&pkthdr->ts, pip.timestamp);

   /* do a little validation */
   if(cap_len < SLIP_HEADER_LEN)
   {
      fprintf(stderr, "SLIP header length < captured len! (%d bytes)\n",
              cap_len);
      return;
   }

   pktidx = pkt;
   pktidx += SLIP_HEADER_LEN;
   
   DecodeIP(pktidx, len - SLIP_HEADER_LEN);     
}



/****************************************************************************
 *
 * Function: DecodeRawPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeRawPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   int pkt_len;  /* suprisingly, the length of the packet */

   pkt_len = pkthdr->len;       /* total packet length */

   ClearDumpBuf();

   bzero((void *) &pip, sizeof(PrintIP));

#ifdef DEBUG
   printf("Packet!\n");
#endif

   bzero(&net, sizeof(NetData));

   ts_print(&pkthdr->ts, pip.timestamp);

   pktidx = pkt;

   DecodeIP(pktidx, pkt_len);

   return;
}



/****************************************************************************
 *
 * Function: DecodeIP(u_char *, int)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeIP(u_char *pkt, const int len)
{
   IPHdr *iph;   /* ip header ptr */
   u_int ip_len; /* length from the start of the ip hdr to the pkt end */
   u_int hlen;   /* ip header length */


   /* lay the IP struct over the raw data */
   iph = (IPHdr *) pkt;

#ifdef DEBUG
   printf("ip header starts at: %p\n", iph);
#endif

   /* do a little validation */
   if(len < sizeof(IPHdr))
   {
      if(pv.verbose_flag)
         fprintf(stderr, "Truncated header! (%d bytes)\n", len);
      
      return;
   }

   ip_len = ntohs(iph->ip_len);

   if(len < ip_len)
   {

      if(pv.verbose_flag)
      {  
         fprintf(stderr,
                 "Truncated packet!  Header says %d bytes, actually %d bytes\n",
                 ip_len, len);

         PrintNetData(stdout, pkt, len);
      }

      if(pv.log_flag)
      {
         OpenLogFile(DUMP);

         PrintNetData(log_ptr, pkt, len);

         fflush(log_ptr);

         fclose(log_ptr);
      }
      
      return;
   }

   /* set the IP header length */
   hlen = iph->ip_hlen * 4;

   if(hlen > 20)
   {
      DecodeIPOptions( (pkt + 20), hlen - 20);
   }

   /* generate a timestamp */
   /*GetTime(pip.timestamp);*/

   /* start filling in the printout data structures */
   strncpy(pip.saddr, inet_ntoa(iph->ip_src), 15);
   strncpy(pip.daddr, inet_ntoa(iph->ip_dst), 15);
   net.sip = iph->ip_src.s_addr;
   net.dip = iph->ip_dst.s_addr;

#ifdef DEBUG
   printf("Src addr = %s\n", pip.saddr);
   printf("Dst addr = %s\n", pip.daddr);
   printf("IP ID field: %X\n", ntohs(iph->ip_id)); 
#endif

   pip.ttl = iph->ip_ttl;
   pip.tos = iph->ip_tos;

   /* check for fragmented packets */
   ip_len -= hlen;
   pip.frag_off = ntohs(iph->ip_off);

#ifdef DEBUG
   printf("IP offset field (host order): %X\n", pip.frag_off);
   printf("Calculated DF bit: %d\n", (pip.frag_off & 0x4000)>>14);
   printf("Calculated MF bit: %d\n", (pip.frag_off & 0x2000)>>13);
#endif

   pip.ip_df = (pip.frag_off & 0x4000) >> 14;
   pip.ip_mf = (pip.frag_off & 0x2000) >> 13;

   pip.frag_off &= 0x1FFF;
   pip.frag_id = ntohs(iph->ip_id);

#ifdef DEBUG
   printf("IP DF: %d   IP MF: %d\n", pip.ip_df, pip.ip_mf);
#endif

   if(pip.frag_off == 0)
   {
#ifdef DEBUG
      printf("IP header length: %d\n", hlen);
#endif

      /* move the packet index to point to the transport layer */
      pktidx = pktidx + hlen;

      switch(iph->ip_proto)
      {
         case IPPROTO_TCP:
                      net.proto = IPPROTO_TCP;
                      strncpy(pip.proto, "TCP", 3);
                      DecodeTCP(pktidx, len-hlen);
                      return;

         case IPPROTO_UDP:
                      net.proto = IPPROTO_UDP;
                      strncpy(pip.proto, "UDP", 3);
                      DecodeUDP(pktidx, len-hlen);
                      return;

         case IPPROTO_ICMP:
                      net.proto = IPPROTO_ICMP;
                      strncpy(pip.proto, "ICMP", 4);
                      DecodeICMP(pktidx, len-hlen);
                      return;

         default:
                return;
      }
   }
   else
   {
      switch(iph->ip_proto)
      {
         case IPPROTO_TCP:
                      net.proto = IPPROTO_TCP;
                      strncpy(pip.proto, "TCP", 3);
                      break;
   
         case IPPROTO_UDP:
                      net.proto = IPPROTO_UDP;
                      strncpy(pip.proto, "UDP", 3);
                      break;

         case IPPROTO_ICMP:
                      net.proto = IPPROTO_ICMP;
                      strncpy(pip.proto, "ICMP", 4);
                      break;

         default:
                      net.proto = IPPROTO_ICMP;
                      strncpy(pip.proto, "UNK", 3);
                      break;
      }

      /* move the packet index to point to the transport layer */
      pktidx = pktidx + hlen;
      pip.data = pktidx;
      pip.dsize = len - hlen;

      if(pv.verbose_flag)   
      {                                
         PrintIPPkt(stdout, net.proto);
      }                     
   
      if(pv.log_flag)               
      {
         OpenLogFile(0);  
                         
         PrintIPPkt(log_ptr, net.proto);
      
         fclose(log_ptr);
      }
   }
}



/****************************************************************************
 *
 * Function: DecodeTCP(u_char *, int)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeTCP(u_char *pkt, const int len)
{
   TCPHdr *tcph;  /* TCP packet header ptr */
   int hlen;      /* TCP header length */

   /* lay TCP on top of the data */
   tcph = (TCPHdr *) pkt;

#ifdef DEBUG
   printf("tcp header starts at: %p\n", tcph);
#endif

   /* stuff more data into the printout data struct */
   pip.sport = ntohs(tcph->th_sport);
   pip.dport = ntohs(tcph->th_dport);
   net.sp = pip.sport;
   net.dp = pip.dport;

#ifdef DEBUG
   printf("s-port = %d:%d   d-port = %d:%d\n", pip.sport, tcph->th_sport, pip.dport, tcph->th_dport);
#endif

#ifdef WORDS_BIGENDIAN
   pip.seq = ntohl(tcph->th_seq);
   pip.ack = ntohl(tcph->th_ack);
#else
   pip.seq = tcph->th_seq;
   pip.ack = tcph->th_ack;
#endif

   pip.win = ntohs(tcph->th_win);
   pip.flags = tcph->th_flags;
   net.tcp_flags = tcph->th_flags & 0x3F;

   hlen = tcph->th_off * 4;

   if(hlen > 20)
   {
      DecodeTCPOptions((u_char *)(pkt+20), (hlen - 20));
   }

   pip.data = (char *)(pkt+hlen);

   pip.dsize = len-hlen;

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_TCP);
   }

   if(!pv.use_rules)
   {
      if(pv.log_flag)
      {
         OpenLogFile(0);

         PrintIPPkt(log_ptr, IPPROTO_TCP);

         fclose(log_ptr);
      }
   }
   else
   {
      ApplyRules();
   }
}


/****************************************************************************
 *
 * Function: DecodeUDP(u_char *, int)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeUDP(u_char *pkt, const int len)
{
   UDPHdr *udph;  /* UDP header struct ptr */

   /* set the ptr to the start of the UDP header */
   udph = (UDPHdr *) pkt;

#ifdef DEBUG
   printf("UDP header starts at: %p\n", udph);
#endif

   /* fill in the printout data structs */
   pip.sport = ntohs(udph->uh_sport);
   pip.dport = ntohs(udph->uh_dport);

   /* fill in the helper struct data */
   net.sp = pip.sport;
   net.dp = pip.dport;

   pip.udp_len = ntohs(udph->uh_len);

   pip.data = (char *)(pkt+8);
   pip.dsize = len-8;


   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_UDP);
   }

   if(!pv.use_rules)
   {
      if(pv.log_flag)
      {
         OpenLogFile(0);

         PrintIPPkt(log_ptr, IPPROTO_UDP);

         fclose(log_ptr);
      }
   }
   else
   {
      ApplyRules();
   }
}





/****************************************************************************
 *
 * Function: DecodeICMP(u_char *, int)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeICMP(u_char *pkt, const int len)
{
   ICMPHdr *icmph;  /* ICMP header struct ptr */
   echoext *ext;    /* header extension for ping packets */

   /* set the header ptr first */
   icmph = (ICMPHdr *) pkt;

   /* set the data ptr */
   pip.data = (char *)(pkt+4);
   pip.dsize = len-4;
   pip.icmp_type = icmph->type;
   pip.icmp_code = icmph->code;

#ifdef DEBUG
   printf("ICMP type: %d   code: %d\n", icmph->code, icmph->type);
#endif
   switch(icmph->type)
   {
      case ICMP_ECHOREPLY:
                         sprintf(pip.icmp_str, "ECHO_REPLY");

                         /* setup the pkt id ans seq numbers */
                         ext = (echoext *)(pkt+sizeof(ICMPHdr));
                         pip.dsize -= sizeof(echoext);
                         pip.data += sizeof(echoext);
                         pip.icmp_id = ext->id;
                         pip.icmp_seqno = ext->seqno;

                         break;

      case ICMP_DEST_UNREACH:
                switch(icmph->code)
                {
                   case ICMP_NET_UNREACH:
                            sprintf(pip.icmp_str,
                                    "NET_UNRCH");
                            break;

                   case ICMP_HOST_UNREACH:
                            sprintf(pip.icmp_str,
                                    "HST_UNRCH");
                            break;

                   case ICMP_PROT_UNREACH:
                            sprintf(pip.icmp_str,
                                    "PROTO_UNRCH");
                            break;

                   case ICMP_PORT_UNREACH:
                            sprintf(pip.icmp_str,
                                    "PORT_UNRCH");
                            break;

                   case ICMP_FRAG_NEEDED:
                            sprintf(pip.icmp_str,
                                    "UNRCH_FRAG_NEEDED");
                            break;

                   case ICMP_SR_FAILED:
                            sprintf(pip.icmp_str,
                                    "UNRCH_SOURCE_ROUTE_FAILED");
                            break;

                   case ICMP_NET_UNKNOWN:
                            sprintf(pip.icmp_str,
                                    "UNRCH_NETWORK_UNKNOWN");
                            break;

                   case ICMP_HOST_UNKNOWN:
                            sprintf(pip.icmp_str,
                                    "UNRCH_HOST_UNKNOWN");
                            break;

                   case ICMP_HOST_ISOLATED:
                            sprintf(pip.icmp_str,
                                    "UNRCH_HOST_ISOLATED");
                            break;

                   case ICMP_NET_ANO:
                            sprintf(pip.icmp_str,
                                    "UNRCH_NET_ANO");
                            break;

                   case ICMP_HOST_ANO:
                            sprintf(pip.icmp_str,
                                    "UNRCH_HOST_ANO");
                            break;

                   case ICMP_NET_UNR_TOS:
                            sprintf(pip.icmp_str,
                                    "UNRCH_NET_UNR_TOS");
                            break;

                   case ICMP_HOST_UNR_TOS:
                            sprintf(pip.icmp_str,
                                    "UNRCH_HOST_UNR_TOS");
                            break;

                   case ICMP_PKT_FILTERED:
                            sprintf(pip.icmp_str,
                                    "UNRCH_PACKET_FILT");
                            break;

                   case ICMP_PREC_VIOLATION:
                            sprintf(pip.icmp_str,
                                    "UNRCH_PREC_VIOL");
                            break;

                  case ICMP_PREC_CUTOFF:
                            sprintf(pip.icmp_str,
                                    "UNRCH_PREC_CUTOFF");
                            break;

                   default:
                            sprintf(pip.icmp_str,
                                    "UNKNOWN");
                            break;

               }
               break;

      case ICMP_SOURCE_QUENCH:
                         sprintf(pip.icmp_str, "SRC_QUENCH");
                         break;

      case ICMP_REDIRECT:
                         sprintf(pip.icmp_str, "REDIRECT");
                         break;

      case ICMP_ECHO:
                         sprintf(pip.icmp_str, "ECHO");

                         /* setup the pkt id ans seq numbers */
                         ext = (echoext *)(pkt+sizeof(ICMPHdr));
                         pip.dsize -= sizeof(echoext);
                         pip.data += sizeof(echoext);
                         pip.icmp_id = ext->id;
                         pip.icmp_seqno = ext->seqno;
                         
                         break;

      case ICMP_TIME_EXCEEDED:
                         sprintf(pip.icmp_str, "TTL_EXCEED");
                         break;

      case ICMP_PARAMETERPROB:
                         sprintf(pip.icmp_str, "PARAM_PROB");
                         break;

      case ICMP_TIMESTAMP:
                         sprintf(pip.icmp_str, "TIMESTAMP");
                         break;

      case ICMP_TIMESTAMPREPLY:
                         sprintf(pip.icmp_str, "TIMESTAMP_RPL");
                         break;

      case ICMP_INFO_REQUEST:
                         sprintf(pip.icmp_str, "INFO_REQ");
                         break;

      case ICMP_INFO_REPLY:
                         sprintf(pip.icmp_str, "INFO_RPL");
                         break;

      case ICMP_ADDRESS:
                         sprintf(pip.icmp_str, "ADDR");
                         break;

      case ICMP_ADDRESSREPLY:
                         sprintf(pip.icmp_str, "ADDR_RPL");
                         break;
      
      default:
                         sprintf(pip.icmp_str, "UNKNOWN");
                         break;
   }

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_ICMP);
   }

   if(!pv.use_rules)
   {
      if(pv.log_flag)
      {
         OpenLogFile(0);

         PrintIPPkt(log_ptr, IPPROTO_ICMP);

         fclose(log_ptr);
      }
   }
   else
   {
      ApplyRules();
   }

   return;
}



/****************************************************************************
 *
 * Function: DecodeARP(u_char *, int)
 *
 * Purpose: Decode ARP stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            caplen => unused...
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeARP(u_char *pkt, int len, int caplen)
{
   EtherARP *arph;        /* ARP hdr ptr */
   char timebuf[64];      /* timestamp buffer */
   struct in_addr saddr;  /* src addr */
   struct in_addr daddr;  /* dest addr */
   char type[32];         /* type buf */

   arph = (EtherARP *) pkt;

   if(len < sizeof(EtherARP))
   {
      printf("Truncated packet\n");
      return;
   }

   /*GetTime(timebuf);*/
   memcpy((void *) &saddr, (void *) &arph->arp_spa, sizeof (struct in_addr));
   memcpy((void *) &daddr, (void *) &arph->arp_tpa, sizeof (struct in_addr));

   switch (ntohs(arph->ea_hdr.ar_op))
   {
      case ARPOP_REQUEST:
                  sprintf(type, "ARP request");
                  break;

      case ARPOP_REPLY:
                  sprintf(type, "ARP reply");
                  break;

      case ARPOP_RREQUEST:
                  sprintf(type, "RARP request");
                  break;

      case ARPOP_RREPLY:
                  sprintf(type, "RARP reply");
                  break;

      default:
                 sprintf(type, "unknown");
                 return;
   }

   if(pv.verbose_flag)
   {
      memcpy((void *) &saddr, (void *) &arph->arp_spa, sizeof (struct in_addr));
      fprintf(stdout, "%s: %s %s", timebuf, "ARP", inet_ntoa(saddr));
      memcpy((void *) &daddr, (void *) &arph->arp_tpa, sizeof (struct in_addr));
      fprintf(stdout, " -> %s  %s\n", inet_ntoa(daddr), type);
   }

   return;
}


/****************************************************************************
 *
 * Function: DecodeIPX(u_char *, int)
 *
 * Purpose: Well, it doesn't do much of anything right now...
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeIPX(u_char *pkt, int len)
{
   printf("IPX packet\n");

   return;
}




/****************************************************************************
 *
 * Function: DecodeTCPOptions(u_char *, int)
 *
 * Purpose: Fairly self explainatory name, don't you think?
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeTCPOptions(u_char *o_list, int o_len)
{
   u_char *cp;
   int i;
   int opt;
   int len; 
   int datalen;
   char tmpbuf[32];

   cp = o_list;

   pip.TO_flag = 1;
   bzero(tmpbuf, 32);

   while (o_len > 0)
   {
      /* Check for zero length options */
      opt = *cp++;

      if((opt == TCPOPT_EOL) || 
         (opt == TCPOPT_NOP))
      {
            len = 1;
      }
      else
      {
         len = *cp++;  /* total including type, len */

         if(len < 2 || len > o_len)
         {
            if(pv.verbose_flag)
            {
               printf("Illegal TCP Options, reported size %d, tcp header reports %d\n", len, o_len);

               PrintNetData(stdout, o_list, o_len);
            }
           
            if(pv.log_flag)
            {
               OpenLogFile(BOGUS);

               fprintf(log_ptr, "Illegal TCP Options, reported size %d, tcp header reports %d\n", len, o_len);

               PrintNetData(log_ptr, o_list, o_len);

               fclose(log_ptr);
            }

            break;
         }

         /* account for length byte */
         o_len--;

      }

      /* account for type byte */
      o_len--;

      /* Handle the rest of the options */
      datalen = 0;

      switch (opt)
      {
         case TCPOPT_MAXSEG:
                  datalen = 2;
                  sprintf(tmpbuf, "MSS: %u ", EXTRACT_16BITS(cp));
                  strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));
                  bzero(tmpbuf, 32);

                  break;

         case TCPOPT_EOL:
                  strncat(pip.TO_Str, "EOL ", 4);
                  break;

         case TCPOPT_NOP:
                  strncat(pip.TO_Str, "NOP ", 4);
                  break;

         case TCPOPT_WSCALE:
                  datalen = 1;
                  sprintf(tmpbuf, "WS: %u ", *cp);
                  strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));
                  break;

         case TCPOPT_ECHO:
                  datalen = 4;
                  sprintf(tmpbuf,"Echo: %u ", EXTRACT_32BITS(cp));
                  strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));
                  break;

         case TCPOPT_ECHOREPLY:
                  datalen = 4;
                  sprintf(tmpbuf, "Echo Rep: %u ", EXTRACT_32BITS(cp));
                  strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));
                  break;

         case TCPOPT_TIMESTAMP:
                  datalen = 8;
                  sprintf(tmpbuf, "TS: %u %u ", EXTRACT_32BITS(cp), EXTRACT_32BITS(cp + 4));
                  strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));
                  break;

         default:
                  datalen = len - 2;
                  sprintf(tmpbuf, "Opt %d:", opt);
                  strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));

                  for(i = 0; i < datalen; ++i)
                  {
                      sprintf(tmpbuf, " %02x", cp[i]);
                      strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));
                  }
                  break;
      }

          /*
           * Account for data printed
           */

          cp += datalen;
          o_len -= datalen;
   }
}



/****************************************************************************
 *
 * Function: DecodeIPOptions(u_char *, int)
 *
 * Purpose: Once again, a fairly self-explainatory name
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeIPOptions(u_char *o_list, int o_len)
{
   u_char *cp;
   int i;
   int opt;
   int len; 
   int datalen;
   char tmpbuf[32];

   cp = o_list;

   pip.IPO_flag = 1;
   bzero(tmpbuf, 32);

   while (o_len > 0)
   {
      /* Check for zero length options */

      opt = *cp++;

      if((opt == IPOPT_EOL) || 
         (opt == IPOPT_NOP))
      {
            len = 1;
      }
      else
      {
         len = *cp++;  /* total including type, len */

         if(len < 2 || len > o_len)
         {
            if(pv.verbose_flag)
            {
               printf("Illegal IP options: option says %d, IP header says %d\n", len, o_len);
               PrintNetData(stdout, o_list, o_len);
            }

            if(pv.log_flag)
            {
               OpenLogFile(BOGUS);
               fprintf(log_ptr, "Illegal IP options: option says %d, IP header says %d\n", len, o_len);

               PrintNetData(log_ptr, o_list, o_len);

               fclose(log_ptr);
            }

            break;
         }

         /* account for length byte */
         o_len--;

      }

      /* account for type byte */
      o_len--;

      /* Handle the rest of the options */
      datalen = 0;

      switch (opt)
      {
         case IPOPT_RR:
                  datalen = len - 2;
                  strncat(pip.IPO_Str, "RR ", 3);

                  break;

         case IPOPT_EOL:
                  strncat(pip.IPO_Str, "EOL ", 4);
                  break;

         case IPOPT_NOP:
                  strncat(pip.IPO_Str, "NOP ", 4);
                  break;

         case IPOPT_TS:
                  datalen = len - 2;
                  strncat(pip.TO_Str, "TS ", 3);
                  break;

         case IPOPT_SECURITY:
                  datalen = len - 2;
                  strncat(pip.TO_Str, "SEC ", 4);
                  break;

         case IPOPT_LSRR:
         case IPOPT_LSRR_E:
                  datalen = len - 2;
                  strncat(pip.TO_Str, "LSRR ", 5);
                  break;

         case IPOPT_SATID:
                  datalen = len - 2;
                  strncat(pip.TO_Str, "SID ", 4);
                  break;

         case IPOPT_SSRR:
                  datalen = len - 2;
                  strncat(pip.TO_Str, "SSRR ", 5);
                  break;

         default:
                  datalen = len - 2;
                  sprintf(tmpbuf, "Opt %d:", opt);
                  strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));

                  for(i = 0; i < datalen; ++i)
                  {
                      sprintf(tmpbuf, " %02x ", cp[i]);
                      strncat(pip.TO_Str, tmpbuf, strlen(tmpbuf));
                  }
                  break;
      }

          /*
           * Account for data printed
           */

          cp += datalen;
          o_len -= datalen;
   }
}




