#include "sp_tcp_flag_check.h"

extern char *file_name;
extern int file_line;

void SetupTCPFlagCheck()
{
   RegisterPlugin("flags", TCPFlagCheckInit);
   
#ifdef DEBUG
   printf("Plugin: TCPFlagCheck Initialized!\n");
#endif
}



void TCPFlagCheckInit(char *data, OptTreeNode *otn, int protocol)
{
   if(protocol != IPPROTO_TCP)
   {
      fprintf(stderr, "ERROR Line %s (%d): TCP Options on non-TCP rule\n", file_name, file_line);
      exit(1);
   }

   otn->ds_list[PLUGIN_TCP_FLAG_CHECK] = (TCPFlagCheckData *)calloc(sizeof(TCPFlagCheckData), sizeof(char));

   /* set up the pattern buffer */
   ParseFlags(data, otn);

   /* link the plugin function in to the current OTN */
   AddOptFuncToList(CheckTcpFlagsEq, otn);

#ifdef DEBUG
   printf("OTN function CheckTcpFlagsEq added to rule!\n");
#endif
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
void ParseFlags(char *rule, OptTreeNode *otn)
{
   char *fptr;
   char *fend;
   TCPFlagCheckData *idx;

   idx = otn->ds_list[PLUGIN_TCP_FLAG_CHECK];
   
   fptr = rule;

   while(!isalnum((u_char) *fptr))
	   fptr++;

   /* find the end of the alert string */
   fend = fptr + strlen(fptr); 

   while(fptr < fend)
   {
      switch((*fptr&0xFF))
      {
         case 'f':
         case 'F':
                 idx->tcp_flags |= R_FIN;
                 break;

         case 's':
         case 'S':
                 idx->tcp_flags |= R_SYN;
                 break;

         case 'r':
         case 'R':
                 idx->tcp_flags |= R_RST;
                 break;

         case 'p':
         case 'P':
                 idx->tcp_flags |= R_PSH;
                 break;

         case 'a':
         case 'A':
                 idx->tcp_flags |= R_ACK;
                 break;

         case 'u':
         case 'U':
                 idx->tcp_flags |= R_URG;
                 break;

         case '0':
		 idx->tcp_flags = 0;
		 break;

         case '1': /* reserved bit flags */
                 idx->tcp_flags |= R_RES1;
                 break;

         case '2': /* reserved bit flags */
                 idx->tcp_flags |= R_RES2;
                 break;

         default:
                 fprintf(stderr, "ERROR Line %s (%d): bad TCP flag = \"%c\"\n", file_name, file_line, *fptr);
                 fprintf(stderr, "      Valid otions: UAPRSF12 or 0 for NO flags (e.g. NULL scan)\n");
                 exit(1);
      }

      fptr++;
   }

}


int CheckTcpFlagsEq(Packet *p, struct _OptTreeNode *otn_idx, OptFpList *fp_list)
{
   TCPFlagCheckData *flagptr;

   flagptr = otn_idx->ds_list[PLUGIN_TCP_FLAG_CHECK];

#ifdef DEBUG
   printf("           <!!> CheckTcpFlagsEq: ");
#endif

   if(flagptr->tcp_flags == p->tcph->th_flags)
   {
#ifdef DEBUG
      printf("Got TCP flag match!\n");
#endif
      return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf("No match\n");
   }
#endif

   return 0;
}

