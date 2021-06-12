#include "sp_ipoption_check.h"

extern char *file_name;  /* this is the file name from rules.c, generally used
                            for error messages */

extern int file_line;    /* this is the file line number from rules.c that is
                            used to indicate file lines for error messages */


/****************************************************************************
 * 
 * Function: SetupTemplate()
 *
 * Purpose: Generic detection engine plugin template.  Registers the
 *          configuration function and links it to a rule keyword.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIpOptionCheck()
{
   /* map the keyword to an initialization/processing function */
   RegisterPlugin("ipopts", IpOptionInit);

#ifdef DEBUG
   printf("Plugin: IpOptionCheck Initialized\n");
#endif
}


/****************************************************************************
 * 
 * Function: TemplateInit(char *, OptTreeNode *)
 *
 * Purpose: Generic rule configuration function.  Handles parsing the rule 
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpOptionInit(char *data, OptTreeNode *otn, int protocol)
{
   /* allocate the data structure and attach it to the
      rule's data struct list */
   otn->ds_list[PLUGIN_IPOPTION_CHECK] = (IpOptionData *) calloc(sizeof(IpOptionData), sizeof(char));

   /* this is where the keyword arguments are processed and placed into the 
      rule option's data structure */
   ParseIpOptionData(data, otn);

   /* finally, attach the option's detection function to the rule's 
      detect function pointer list */
   AddOptFuncToList(CheckIpOptions, otn);
}



/****************************************************************************
 * 
 * Function: TemplateRuleParseFunction(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseIpOptionData(char *data, OptTreeNode *otn)
{
   IpOptionData *ds_ptr;  /* data struct pointer */

   /* set the ds pointer to make it easier to reference the option's
      particular data struct */
   ds_ptr = otn->ds_list[PLUGIN_IPOPTION_CHECK];

   if(data == NULL)
   {
      fprintf(stderr, "ERROR %s (%d) => IP Option keyword missing argument!\n", file_name, file_line);
 
      exit(1);
   }

   while(isspace((u_char)*data))
      data++; 
 

   if(!strncasecmp(data, "rr", 2))
   {
      ds_ptr->ip_option = IPOPT_RR;
      return;
   }
   else if(!strncasecmp(data, "eol", 3))
   {
      ds_ptr->ip_option = IPOPT_EOL;
      return;
   }
   else if(!strncasecmp(data, "nop", 3))
   {
      ds_ptr->ip_option = IPOPT_NOP;
      return;
   }
   else if(!strncasecmp(data, "ts", 2))
   {
      ds_ptr->ip_option = IPOPT_TS;
      return;
   }
   else if(!strncasecmp(data, "sec", 3))
   {
      ds_ptr->ip_option = IPOPT_SECURITY;
      return;
   }
   else if(!strncasecmp(data, "lsrr", 4))
   {
      ds_ptr->ip_option = IPOPT_LSRR;
      return;
   }
   else if(!strncasecmp(data, "lsrre", 5))
   {
      ds_ptr->ip_option = IPOPT_LSRR_E;
      return;
   }
   else if(!strncasecmp(data, "satid", 5))
   {
      ds_ptr->ip_option = IPOPT_SATID;
      return;
   }
   else if(!strncasecmp(data, "ssrr", 3))
   {
      ds_ptr->ip_option = IPOPT_SSRR;
      return;
   }
   else
   {
      fprintf(stderr, "ERROR %s (%d) => Unknown IP option argument: %s!\n", file_name, file_line, data);

      exit(1);
   }
}


/****************************************************************************
 * 
 * Function: TemplateDetectorFunction(char *, OptTreeNode *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
int CheckIpOptions(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
   int i;
#ifdef DEBUG
   printf("CheckIpOptions:");
#endif

   for(i=0; i<p->ip_option_count; i++)
   {

#ifdef DEBUG
      printf("testing pkt(%d):rule(%d)\n",((IpOptionData *)otn->ds_list[PLUGIN_IPOPTION_CHECK])->ip_option, p->ip_options[i].code); 
#endif

      if(((IpOptionData *)otn->ds_list[PLUGIN_IPOPTION_CHECK])->ip_option == p->ip_options[i].code)
      {
         /* call the next function in the function list recursively */
         return fp_list->next->OptTestFunc(p, otn, fp_list->next);
      }
   }

   /* if the test isn't successful, return 0 */
   return 0;
}
