#include "sp_tcp_seq_check.h"

extern char *file_name;  /* this is the file name from rules.c, generally used
                            for error messages */

extern int file_line;    /* this is the file line number from rules.c that is
                            used to indicate file lines for error messages */


/****************************************************************************
 * 
 * Function: SetupTcpSeqCheck()
 *
 * Purpose: Link the seq keyword to the initialization function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupTcpSeqCheck()
{
   /* map the keyword to an initialization/processing function */
   RegisterPlugin("seq", TcpSeqCheckInit);

#ifdef DEBUG
   printf("Plugin: TcpSeqCheck Initialized\n");
#endif
}


/****************************************************************************
 * 
 * Function: TcpSeqCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Attach the option data to the rule data struct and link in the
 *          detection function to the function pointer list.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void TcpSeqCheckInit(char *data, OptTreeNode *otn, int protocol)
{
   if(protocol != IPPROTO_TCP)
   {
      fprintf(stderr, "ERROR Line %s (%d): TCP Options on non-TCP rule\n", file_name, file_line);
      exit(1);
   }

   /* allocate the data structure and attach it to the
      rule's data struct list */
   otn->ds_list[PLUGIN_TCP_ACK_CHECK] = (TcpSeqCheckData *) calloc(sizeof(TcpAckCheckData), sizeof(char));

   /* this is where the keyword arguments are processed and placed into the 
      rule option's data structure */
   ParseTcpSeq(data, otn);

   /* finally, attach the option's detection function to the rule's 
      detect function pointer list */
   AddOptFuncToList(CheckTcpSeqEq, otn);
}



/****************************************************************************
 * 
 * Function: ParseTcpSeq(char *, OptTreeNode *)
 *
 * Purpose: Attach the option rule's argument to the data struct.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseTcpSeq(char *data, OptTreeNode *otn)
{
   TcpSeqCheckData *ds_ptr;  /* data struct pointer */

   /* set the ds pointer to make it easier to reference the option's
      particular data struct */
   ds_ptr = otn->ds_list[PLUGIN_TCP_ACK_CHECK];

   while(isspace((int)*data))
   {
      data++;
   }

   ds_ptr->tcp_seq = atoi(data);

#ifdef DEBUG
   printf("Seq set to %lX\n", ds_ptr->tcp_seq);
#endif

}


/****************************************************************************
 * 
 * Function: CheckTcpSeqEq(char *, OptTreeNode *)
 *
 * Purpose: Check to see if the packet's TCP ack field is equal to the rule
 *          ack value.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int CheckTcpSeqEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
   if(((TcpSeqCheckData *)otn->ds_list[PLUGIN_TCP_ACK_CHECK])->tcp_seq == ntohl(p->tcph->th_seq))
   {
      /* call the next function in the function list recursively */
      return fp_list->next->OptTestFunc(p, otn, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      /* you can put debug comments here or not */
      printf("No match\n");
   }
#endif

   /* if the test isn't successful, return 0 */
   return 0;
}
