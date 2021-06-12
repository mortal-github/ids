#include "sp_icmp_type_check.h"

extern char *file_name;  /* this is the file name from rules.c, generally used
                            for error messages */

extern int file_line;    /* this is the file line number from rules.c that is
                            used to indicate file lines for error messages */


/****************************************************************************
 * 
 * Function: SetupIcmpTypeCheck()
 *
 * Purpose: Register the itype keyword and configuration function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIcmpTypeCheck()
{
   /* map the keyword to an initialization/processing function */
   RegisterPlugin("itype", IcmpTypeCheckInit);

#ifdef DEBUG
   printf("Plugin: IcmpTypeCheck Initialized\n");
#endif
}


/****************************************************************************
 * 
 * Function: IcmpTypeCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Initialize the rule data structs and parse the rule argument
 *          data, then link in the detection function
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IcmpTypeCheckInit(char *data, OptTreeNode *otn, int protocol)
{
   if(protocol != IPPROTO_ICMP)
   {
      fprintf(stderr, "ERROR Line %s (%d): ICMP Options on non-ICMP rule\n", file_name, file_line);
      exit(1);
   }

   /* allocate the data structure and attach it to the
      rule's data struct list */
   otn->ds_list[PLUGIN_ICMP_TYPE] = (IcmpTypeCheckData *) calloc(sizeof(IcmpTypeCheckData), sizeof(char));

   /* this is where the keyword arguments are processed and placed into the 
      rule option's data structure */
   ParseIcmpType(data, otn);

   /* finally, attach the option's detection function to the rule's 
      detect function pointer list */
   AddOptFuncToList(IcmpTypeCheck, otn);
}



/****************************************************************************
 * 
 * Function: ParseIcmpType(char *, OptTreeNode *)
 *
 * Purpose: Process the itype argument and stick it in the data struct
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseIcmpType(char *data, OptTreeNode *otn)
{
   char *type;
   IcmpTypeCheckData *ds_ptr;  /* data struct pointer */

   /* set the ds pointer to make it easier to reference the option's
      particular data struct */
   ds_ptr = otn->ds_list[PLUGIN_ICMP_TYPE];

   /* set a pointer to the data so to leave the original unchanged */
   type = data;

   /* get rid of spaces before the data */
   while(isspace((int)*data))
      data++;

   /* make sure this is a number (maybe someday this can handle ICMP type
      strings as well */
   if(isdigit((int)*data))
   {
      /* set the icmp type value */
      ds_ptr->icmp_type = atoi(data);

      /* all done */
      return;
   }
   else  /* uh oh */
   {
      fprintf(stderr, "ERROR Line %s (%d): Bad ICMP type: %s\n", file_name, 
              file_line, data);
      exit(1);
   }  
}


/****************************************************************************
 * 
 * Function: IcmpTypeCheck(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's ICMP type field value against the option's
 *          ICMP type
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int IcmpTypeCheck(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
   if(((IcmpTypeCheckData *) otn->ds_list[PLUGIN_ICMP_TYPE])->icmp_type == p->icmph->type)
   {
#ifdef DEBUG
      printf("Got icmp type match!\n");
#endif

      /* call the next function in the function list recursively */
      return fp_list->next->OptTestFunc(p, otn, fp_list->next);
   }
#ifdef DEBUG
   else
   {
      printf("icmp type mismatch!\n");
   }
#endif

   /* return 0 on failed test */
   return 0;
}
