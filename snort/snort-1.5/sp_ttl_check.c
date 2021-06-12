#include "sp_ttl_check.h"

extern char *file_name;  /* this is the file name from rules.c, generally used
                            for error messages */

extern int file_line;    /* this is the file line number from rules.c that is
                            used to indicate file lines for error messages */


/****************************************************************************
 * 
 * Function: SetupTtlCheck()
 *
 * Purpose: Register the ttl option keyword with its setup function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupTtlCheck()
{
   /* map the keyword to an initialization/processing function */
   RegisterPlugin("ttl", TtlCheckInit);

#ifdef DEBUG
   printf("Plugin: TTLCheck Initialized\n");
#endif
}


/****************************************************************************
 * 
 * Function: TtlCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Parse the ttl keyword arguments and link the detection module
 *          into the function list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void TtlCheckInit(char *data, OptTreeNode *otn, int protocol)
{
   /* allocate the data structure and attach it to the
      rule's data struct list */
   otn->ds_list[PLUGIN_TTL_CHECK] = (TtlCheckData *) calloc(sizeof(TtlCheckData), sizeof(char));

   /* this is where the keyword arguments are processed and placed into the 
      rule option's data structure */
   ParseTtl(data, otn);

   /* finally, attach the option's detection function to the rule's 
      detect function pointer list */
   AddOptFuncToList(CheckTtlEq, otn);
}



/****************************************************************************
 * 
 * Function: ParseTtl(char *, OptTreeNode *)
 *
 * Purpose: Parse the TTL keyword's arguments
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseTtl(char *data, OptTreeNode *otn)
{
   TtlCheckData *ds_ptr;  /* data struct pointer */

   /* set the ds pointer to make it easier to reference the option's
      particular data struct */
   ds_ptr = otn->ds_list[PLUGIN_TTL_CHECK];

   /* advance past whitespace */
   while(isspace((int)*data)) data++;

   ds_ptr->ttl = atoi(data);

#ifdef DEBUG
   printf("Set TTL to %d\n", ds_ptr->ttl);
#endif

}


/****************************************************************************
 * 
 * Function: CheckTtlEq(char *, OptTreeNode *)
 *
 * Purpose: Test if the packet TTL equals the rule option's ttl
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
   /* your detection function tests go here */
   if(((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl == p->iph->ip_ttl)
   {
      /* call the next function in the function list recursively */
      return fp_list->next->OptTestFunc(p, otn, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      /* you can put debug comments here or not */
      printf("TTL not equal\n");
   }
#endif

   /* if the test isn't successful, return 0 */
   return 0;
}
