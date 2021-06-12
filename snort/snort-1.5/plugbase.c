#include "plugbase.h"

KeywordXlateList *KeywordList;
PreprocessKeywordList *PreprocessKeywords;
PreprocessFuncNode *PreprocessList;

extern int file_line;
extern char *file_name;

void InitPlugIns()
{
   printf("Initializing Plug-ins!\n");

   SetupPatternMatch();
   SetupTCPFlagCheck();
   SetupIcmpTypeCheck();
   SetupIcmpCodeCheck();
   SetupTtlCheck();
   SetupIpIdCheck();
   SetupTcpAckCheck();
   SetupTcpSeqCheck();
   SetupDsizeCheck();
   SetupIpOptionCheck();
}


void InitPreprocessors()
{
   printf("Initializing Preprocessors!\n");
   
   SetupHttpDecode();
   SetupMinfrag();

}


/****************************************************************************
 *
 * Function: RegisterPlugin(char *, void (*func)())
 *
 * Purpose:  Associates a rule option keyword with an option setup/linking
 *           function.
 *
 * Arguments: keyword => The option keyword to associate with the option 
 *                       handler
 *            *func => function pointer to the handler 
 *
 * Returns: void function
 *
 ***************************************************************************/
void RegisterPlugin(char *keyword, void (*func)(char *, OptTreeNode *, int))
{
   KeywordXlateList *idx;

#ifdef DEBUG
   printf("Registering keyword:func => %s:%p\n", keyword, func);
#endif

   idx = KeywordList;

   if(idx == NULL)
   {
      KeywordList = (KeywordXlateList *) calloc(sizeof(KeywordXlateList), sizeof(char));

      KeywordList->entry.keyword = (char *) calloc(strlen(keyword)+1, sizeof(char));
      strncpy(KeywordList->entry.keyword, keyword, strlen(keyword));
      KeywordList->entry.func = func;
   }
   else
   {
      /* go to the end of the list */
      while(idx->next != NULL)
      {
         if(!strncasecmp(idx->entry.keyword, keyword, strlen(keyword)))
         {
            fprintf(stderr, "ERROR %s (%d) => Duplicate detection plugin keyword!\n", file_name, file_line);

            exit(1);
         }
         
         idx = idx->next;
      }

      idx->next = (KeywordXlateList *) calloc(sizeof(KeywordXlateList), sizeof(char));

      idx = idx->next;

      idx->entry.keyword = (char *) calloc(strlen(keyword)+1, sizeof(char));
      strncpy(idx->entry.keyword, keyword, strlen(keyword));
      idx->entry.func = func;
   }
}




/****************************************************************************
 *
 * Function: DumpPlugIns()
 *
 * Purpose:  Prints the keyword->function list
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpPlugIns()
{
   KeywordXlateList *idx;

   idx = KeywordList;

   printf("-------------------------------------------------\n");
   printf(" Keyword     |      Plugin Registered @\n");  
   printf("-------------------------------------------------\n");
   while(idx != NULL)
   {
      printf("%-13s:      %p\n", idx->entry.keyword, idx->entry.func);
      idx = idx->next;
   }
   printf("-------------------------------------------------\n\n");
}



/****************************************************************************
 *
 * Function: RegisterPlugin(char *, void (*func)())
 *
 * Purpose:  Associates a rule option keyword with an option setup/linking
 *           function.
 *
 * Arguments: keyword => The option keyword to associate with the option 
 *                       handler
 *            *func => function pointer to the handler 
 *
 * Returns: void function
 *
 ***************************************************************************/
void RegisterPreprocessor(char *keyword, void (*func)(u_char *))
{
   PreprocessKeywordList *idx;

#ifdef DEBUG
   printf("Registering keyword:preproc => %s:%p\n", keyword, func);
#endif

   idx = PreprocessKeywords;

   if(idx == NULL)
   {
      /* alloc the node */
      PreprocessKeywords = (PreprocessKeywordList *) calloc(sizeof(PreprocessKeywordList), sizeof(char));
 
      /* alloc space for the keyword */
      PreprocessKeywords->entry.keyword = (char *) calloc(strlen(keyword)+1, sizeof(char));

      /* copy the keyword into the struct */
      strncpy(PreprocessKeywords->entry.keyword, keyword, strlen(keyword));

      /* set the function pointer to the keyword handler function */
      PreprocessKeywords->entry.func = (void *) func;
   }
   else
   {
      /* loop to the end of the list */
      while(idx->next != NULL)
      {
         if(!strncasecmp(idx->entry.keyword, keyword, strlen(keyword)))
         {
            fprintf(stderr, "ERROR %s (%d) => Duplicate preprocessor keyword!\n", file_name, file_line);

            exit(1);
         }

         idx = idx->next;
      }

      idx->next = (PreprocessKeywordList *) calloc(sizeof(PreprocessKeywordList), sizeof(char));
   
      idx = idx->next;

     /* alloc space for the keyword */
      idx->entry.keyword = (char *) calloc(strlen(keyword)+1, sizeof(char));

      /* copy the keyword into the struct */
      strncpy(idx->entry.keyword, keyword, strlen(keyword));

      /* set the function pointer to the keyword handler function */
      idx->entry.func = (void *) func;
   }
}




/****************************************************************************
 *
 * Function: DumpPreprocessors()
 *
 * Purpose:  Prints the keyword->preprocess list
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpPreprocessors()
{
   PreprocessKeywordList *idx;

   idx = PreprocessKeywords;

   printf("-------------------------------------------------\n");
   printf(" Keyword     |       Preprocessor @ \n");  
   printf("-------------------------------------------------\n");
   while(idx != NULL)
   {
      printf("%-13s:       %p\n", idx->entry.keyword, idx->entry.func);
      idx = idx->next;
   }
   printf("-------------------------------------------------\n\n");
}
