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
   Packet p;

   bzero(&p, sizeof(Packet));

   p.pkth = pkthdr;
   p.pkt = pkt;

   /* set the lengths we need */
   pkt_len = pkthdr->len;       /* total packet length */
   cap_len = pkthdr->caplen;    /* captured packet length */

   if(snaplen < pkt_len)
      pkt_len = cap_len;

#ifdef DEBUG
   printf("Packet!\n");
   printf("caplen: %d    pktlen: %d\n", cap_len, pkt_len);
#endif

   /* do a little validation */
   if(p.pkth->caplen < ETHERNET_HEADER_LEN)
   {
      if(pv.verbose_flag)
         fprintf(stderr, "Captured data length < Ethernet header length! (%d bytes)\n", p.pkth->caplen);
      return;
   }

   /* lay the ethernet structure over the packet data */
   p.eh = (EtherHdr *) pkt;

   /* grab out the network type */

#ifdef DEBUG
   fprintf(stdout, "%X   %X\n", *p.eh->ether_src, *p.eh->ether_dst);
#endif

   switch(ntohs(p.eh->ether_type))
   {
      case ETHERNET_TYPE_IP:
                      DecodeIP(p.pkt+ETHERNET_HEADER_LEN, pkt_len-ETHERNET_HEADER_LEN, &p);
                      return;

      case ETHERNET_TYPE_ARP:
      case ETHERNET_TYPE_REVARP:
                      pc.arp++;
                      if(pv.showarp_flag)
                      {
                         DecodeARP(p.pkt+ETHERNET_HEADER_LEN, pkt_len-ETHERNET_HEADER_LEN, &p);
                
                         if(pv.verbose_flag)
                         {
                            PrintArpHeader(stdout, &p);
                         }

                         if(pv.log_flag)
                         {
                            LogArpPkt(&p);
                         }
                      }

                      return;

      case ETHERNET_TYPE_IPX:
                      pc.ipx++;
                      if(pv.showipx_flag)
                         DecodeIPX(p.pkt+ETHERNET_HEADER_LEN, (pkt_len-ETHERNET_HEADER_LEN));
                      return;

      default:
             pc.other++;
             return;
   }

   return;
}




/****************************************************************************
 *
 * Function: DecodeNullPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: Decoding on loopback devices.
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeNullPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   u_int len;
   u_int cap_len;
   Packet p;

   p.pkth = pkthdr;
   p.pkt = pkt;

   len = pkthdr->len;
   cap_len = pkthdr->caplen;

#ifdef DEBUG
   printf("Packet!\n");
#endif

   /* do a little validation */
   if(cap_len < NULL_HDRLEN)
   {
      fprintf(stderr, "NULL header length < captured len! (%d bytes)\n",
              cap_len);
      return;
   }

   DecodeIP(p.pkt + NULL_HDRLEN, len - NULL_HDRLEN, &p);
}

/****************************************************************************
 *
 * Function: DecodeTRPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: Decode Token Ring packets!
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeTRPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   int pkt_len;  /* suprisingly, the length of the packet */
   int cap_len;  /* caplen value */
   Packet p;

   bzero(&p, sizeof(Packet));

   p.pkth = pkthdr;
   p.pkt = pkt;

   /* set the lengths we need */
   pkt_len = pkthdr->len;       /* total packet length */
   cap_len = pkthdr->caplen;    /* captured packet length */

   if(snaplen < pkt_len)
      pkt_len = cap_len;

#ifdef DEBUG
   printf("Packet!\n");
   printf("caplen: %d    pktlen: %d\n", cap_len, pkt_len);
#endif

   /* do a little validation */
   if(p.pkth->caplen < TR_HLEN)
   {
      if(pv.verbose_flag)
         fprintf(stderr, "Captured data length < Token Ring header length! (%d < %d bytes)\n", p.pkth->caplen, TR_HLEN);
/*      return;*/
   }

   /* lay the ethernet structure over the packet data */
   p.trh = (TRHeader *) pkt;

#ifdef DEBUG
    printf("%2X:%2X:%2X:%2X:%2X:%2X -> %2X:%2X:%2X:%2X:%2X:%2X\n", p.trh->th.trn_shost[0], p.trh->th.trn_shost[1], p.trh->th.trn_shost[2], p.trh->th.trn_shost[3], p.trh->th.trn_shost[4], p.trh->th.trn_shost[5], p.trh->th.trn_dhost[0], p.trh->th.trn_dhost[1], p.trh->th.trn_dhost[2], p.trh->th.trn_dhost[3], p.trh->th.trn_dhost[4], p.trh->th.trn_dhost[5]);
    printf("Protocol: %d\n", p.trh->tl.ethType);
#endif

   pkt_len -= TR_HLEN;
   cap_len -= TR_HLEN;

   switch(htons(p.trh->tl.ethType))
   {
      case ETHERNET_TYPE_IP:
#ifdef DEBUG
                      printf("Decoding IP\n");
#endif
                      DecodeIP(p.pkt+TR_HLEN, pkt_len, &p);
                      return;

      case ETHERNET_TYPE_ARP:
      case ETHERNET_TYPE_REVARP:
#ifdef DEBUG
                      printf("Decoding ARP\n");
#endif
                      pc.arp++;
                      if(pv.showarp_flag)
                      {
                         DecodeARP(p.pkt+TR_HLEN, pkt_len, &p);
                
                         if(pv.verbose_flag)
                         {
                            PrintArpHeader(stdout, &p);
                         }

                         if(pv.log_flag)
                         {
                            LogArpPkt(&p);
                         }
                      }

                      return;

      case ETHERNET_TYPE_IPX:
                      pc.ipx++;
                      if(pv.showipx_flag)
                         DecodeIPX(p.pkt+TR_HLEN, pkt_len);
                      return;

      default:
#ifdef DEBUG
                      printf("Unknown network protocol: %d\n", htons(p.trh->tl.ethType));
#endif
             pc.other++;
             return;
   }

   return;
}




/****************************************************************************
 *
 * Function: DecodePppPkt(char *, struct pcap_pkthdr*, u_char*)
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
void DecodePppPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   u_int len;
   u_int cap_len;
   Packet p;

   p.pkth = pkthdr;
   p.pkt = pkt;
/*
   p.ip_options[0] = 0;
   p.tcp_options[0] = 0;
*/
   len = pkthdr->len;
   cap_len = pkthdr->caplen;

#ifdef DEBUG
   printf("Packet!\n");
#endif

   /* do a little validation */
   if(cap_len < PPP_HDRLEN)
   {
      fprintf(stderr, "PPP header length < captured len! (%d bytes)\n",
              cap_len);
      return;
   }

   DecodeIP(p.pkt + PPP_HDRLEN, len - PPP_HDRLEN, &p);
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
   Packet p;

   p.pkth = pkthdr;
   p.pkt = pkt;

   len = pkthdr->len;
   cap_len = pkthdr->caplen;

#ifdef DEBUG
   printf("Packet!\n");
#endif

   /* do a little validation */
   if(cap_len < SLIP_HEADER_LEN)
   {
      fprintf(stderr, "SLIP header length < captured len! (%d bytes)\n",
              cap_len);
      return;
   }

   DecodeIP(p.pkt + SLIP_HEADER_LEN, cap_len - SLIP_HEADER_LEN, &p);     
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
   Packet p;

   p.pkth = pkthdr;
   p.pkt = pkt;

#ifdef DEBUG
   printf("Packet!\n");
#endif

   DecodeIP(pkt, p.pkth->caplen, &p);

   return;
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
void DecodeI4LRawIPPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   Packet p;

   p.pkth = pkthdr;
   p.pkt = pkt;

#ifdef DEBUG
   printf("Packet!\n");
#endif

   DecodeIP(pkt + 2, p.pkth->len - 2, &p);

   return;
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
void DecodeI4LCiscoIPPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
   Packet p;

   p.pkth = pkthdr;
   p.pkt = pkt;

#ifdef DEBUG
   printf("Packet!\n");
#endif

   DecodeIP(pkt + 4, p.pkth->len - 4, &p);

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
void DecodeIP(u_char *pkt, const int len, Packet *p)
{
   u_int ip_len; /* length from the start of the ip hdr to the pkt end */
   u_int hlen;   /* ip header length */


   /* lay the IP struct over the raw data */
   p->iph = (IPHdr *) pkt;

#ifdef DEBUG
   printf("ip header starts at: %p\n", p->iph);
#endif

   /* do a little validation */
   if(len < IP_HEADER_LEN)
   {
      if(pv.verbose_flag)
         fprintf(stderr, "IP header truncated! (%d bytes)\n", len);
      
      return;
   }

   ip_len = ntohs(p->iph->ip_len);

   /* set the IP header length */
   hlen = p->iph->ip_hlen * 4;

   /* test for IP options */
   if(p->iph->ip_hlen > 5)
   {
      DecodeIPOptions((pkt + IP_HEADER_LEN), hlen - IP_HEADER_LEN, p);
   }

   /* set the remaining packet length */
   ip_len -= hlen;

   /* check for fragmented packets */
   p->frag_offset = ntohs(p->iph->ip_off);

   /* get the values of the more fragments and don't fragment flags */
   p->df = (p->frag_offset & 0x4000) >> 14;
   p->mf = (p->frag_offset & 0x2000) >> 13;

   /* mask off the high bits in the fragment offset field */
   p->frag_offset &= 0x1FFF;

   if(p->frag_offset || p->mf)
   {
      /* set the packet fragment flag */
      p->frag_flag = 1;
   }

   /* if this packet isn't a fragment */
   if(!(p->frag_flag))
   {
      /* set the packet fragment flag */
      p->frag_flag = 0;

#ifdef DEBUG
      printf("IP header length: %d\n", hlen);
#endif

      switch(p->iph->ip_proto)
      {
         case IPPROTO_TCP:
                      pc.tcp++;
                      DecodeTCP(pkt + hlen, len - hlen, p);
                      ClearDumpBuf();
                      return;

         case IPPROTO_UDP:
                      pc.udp++;
                      DecodeUDP(pkt + hlen, len - hlen, p);
                      ClearDumpBuf();
                      return;

         case IPPROTO_ICMP:
                      pc.icmp++;
                      DecodeICMP(pkt + hlen, len - hlen, p);
                      ClearDumpBuf();
                      return;

         default:
                pc.other++;
                ClearDumpBuf();
                return;
      }
   }
   else /* if the packet is fragmented */
   {

      /* increment the packet counter */
      switch(p->iph->ip_proto)
      {
         case IPPROTO_TCP:
                      pc.tcp++;
                      break;
   
         case IPPROTO_UDP:
                      pc.udp++;
                      break;

         case IPPROTO_ICMP:
                      pc.icmp++;
                      break;

         default:
                      pc.other++;
                      break;
      }

      /* set the payload pointer and payload size */
      p->data = pkt + hlen;
      p->dsize = len - hlen;

      /* print the packet to the screen */
      if(pv.verbose_flag)   
      {                                
         PrintIPPkt(stdout, p->iph->ip_proto, p);
      }                     
   
      /* check or log the packet as necessary */
      if(!pv.use_rules)
      {
         if(pv.log_flag)
         {
            if(pv.logbin_flag)
            {
               LogBin(p);
            }
            else
            {
               LogPkt(p);
            }
         }
      }
      else
      {
         Preprocess(p);
      }

      ClearDumpBuf();
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
void DecodeTCP(u_char *pkt, const int len, Packet *p)
{
   int hlen;      /* TCP header length */

   /* lay TCP on top of the data */
   p->tcph = (TCPHdr *) pkt;

#ifdef DEBUG
   printf("tcp header starts at: %p\n", p->tcph);
#endif

   /* stuff more data into the printout data struct */
   p->sp = ntohs(p->tcph->th_sport);
   p->dp = ntohs(p->tcph->th_dport);

   /* multiply the payload offset value by 4 */
   hlen = p->tcph->th_off << 2;

   /* if options are present, decode them */
   if(hlen > 20)
   {
#ifdef DEBUG
      printf("%d bytes of tcp options....\n", hlen - 20);
#endif
      DecodeTCPOptions((u_char *)(pkt+20), (hlen - 20), p);
   }

   /* set the data pointer and size */
   p->data = (u_char *)(pkt + hlen);

   if(hlen < len)
   {
      p->dsize = len - hlen;
   }
   else
   {
      p->dsize = 0;
   }

   /* print/log/test the packet */
   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_TCP, p);
   }

   if(!pv.use_rules)
   {
      if(pv.log_flag)
      {
         if(pv.logbin_flag)
         {
            LogBin(p);
         }
         else
         {
            LogPkt(p);
         }
      }
   }
   else
   {
      Preprocess(p);
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
void DecodeUDP(u_char *pkt, const int len, Packet *p)
{
   /* set the ptr to the start of the UDP header */
   p->udph = (UDPHdr *) pkt;

#ifdef DEBUG
   printf("UDP header starts at: %p\n", p->udph);
#endif

   /* fill in the printout data structs */
   p->sp = ntohs(p->udph->uh_sport);
   p->dp = ntohs(p->udph->uh_dport);

   p->data = (u_char *)(pkt + UDP_HEADER_LEN);

   if((len - UDP_HEADER_LEN) > 0)
   {
      p->dsize = len - UDP_HEADER_LEN;
   }
   else
   {
      p->dsize = 0;
   }

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_UDP, p);
   }

   if(!pv.use_rules)
   {
      if(pv.log_flag)
      {
         if(pv.logbin_flag)
           LogBin(p);
         else
           LogPkt(p);
      }
   }
   else
   {
      Preprocess(p);
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
void DecodeICMP(u_char *pkt, const int len, Packet *p)
{
   /* set the header ptr first */
   p->icmph = (ICMPHdr *) pkt;

   p->dsize = len - ICMP_HEADER_LEN;
   p->data = pkt + ICMP_HEADER_LEN;

#ifdef DEBUG
   printf("ICMP type: %d   code: %d\n", p->icmph->code, p->icmph->type);
#endif
   switch(p->icmph->type)
   {
      case ICMP_ECHOREPLY:
                         /* setup the pkt id ans seq numbers */
                         p->ext = (echoext *)(pkt + ICMP_HEADER_LEN);
                         p->dsize -= sizeof(echoext);
                         p->data += sizeof(echoext);
                         break;
      case ICMP_ECHO:
                         /* setup the pkt id ans seq numbers */
                         p->ext = (echoext *)(pkt + ICMP_HEADER_LEN);
                         p->dsize -= 4;  /* add the size of the echo ext to 
                                            the data ptr and subtract it from
                                            the data size */
                         p->data += 4;
                         break;
   }

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_ICMP, p);
   }

   if(!pv.use_rules)
   {
      if(pv.log_flag)
      {
         if(pv.logbin_flag)
            LogBin(p);
         else
            LogPkt(p);
      }
   }
   else
   {
      Preprocess(p);
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
void DecodeARP(u_char *pkt, int len, Packet *p)
{
   p->ah = (EtherARP *) pkt;

   if(len < sizeof(EtherARP))
   {
      if(pv.verbose_flag)
         printf("Truncated packet\n");
      return;
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
   if(pv.verbose_flag)
   {
      puts("IPX packet");
   }

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
void DecodeTCPOptions(u_char *o_list, int o_len, Packet *p)
{
   u_char *option_ptr;
   int bytes_processed;
   int current_option;

   option_ptr = o_list;
   bytes_processed = 0;
   current_option = 0;

   while((bytes_processed < o_len) && (current_option < 40))
   {
      p->tcp_options[current_option].code = *option_ptr;   

      switch(*option_ptr)
      {
         case TCPOPT_NOP:
         case TCPOPT_EOL:
            p->tcp_options[current_option].len = 0;
            p->tcp_options[current_option].data = NULL;
            bytes_processed++;
            current_option++;
            option_ptr++;
            break;

         case TCPOPT_SACKOK:
            p->tcp_options[current_option].len = 0;
            p->tcp_options[current_option].data = NULL;
            bytes_processed+=2;
            option_ptr+=2;
            current_option++;
            break;

         case TCPOPT_WSCALE:
            p->tcp_options[current_option].len = 3;
            p->tcp_options[current_option].data = option_ptr+2;
            option_ptr+=3;
            bytes_processed+=3;
            current_option++;
            break;
            
         default:            
            p->tcp_options[current_option].len = *(option_ptr+1);

            if(p->tcp_options[current_option].len > 40)
            {
                p->tcp_options[current_option].len = 40;
            }

            p->tcp_options[current_option].data = option_ptr+2;
            option_ptr+= p->tcp_options[current_option].len;
            bytes_processed+= p->tcp_options[current_option].len;
            current_option++;
            break;
      }
   }

   p->tcp_option_count = current_option;
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
void DecodeIPOptions(u_char *o_list, int o_len, Packet *p)
{
   u_char *option_ptr;
   int bytes_processed;
   int current_option;

   option_ptr = o_list;
   bytes_processed = 0;
   current_option = 0;

   while((bytes_processed < o_len) && (current_option < 40))
   {
      p->ip_options[current_option].code = *option_ptr;   
   
      switch(*option_ptr)
      {
         case IPOPT_NOP:
         case IPOPT_EOL:
            p->ip_options[current_option].len = 0;
            p->ip_options[current_option].data = NULL;
            bytes_processed++;
            current_option++;
            option_ptr++;

            break;

         default:
            p->ip_options[current_option].len = *(option_ptr+1);

            if(p->ip_options[current_option].len > 40)
            {
                p->ip_options[current_option].len = 40;
            }

            p->ip_options[current_option].data = option_ptr+2;
            option_ptr+= p->ip_options[current_option].len;
            bytes_processed+= p->ip_options[current_option].len;
            current_option++;
            break;

      }
   }

   p->ip_option_count = current_option;

}

