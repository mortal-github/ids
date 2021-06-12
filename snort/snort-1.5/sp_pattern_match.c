#include "sp_pattern_match.h"

extern int file_line;

void SetupPatternMatch()
{
   RegisterPlugin("content", PayloadSearchInit);
   RegisterPlugin("offset", PayloadSearchOffset);
   RegisterPlugin("depth", PayloadSearchDepth);
   
#ifdef DEBUG
   printf("Plugin: PatternMatch Initialized!\n");
#endif
}



void PayloadSearchInit(char *data, OptTreeNode *otn, int protocol)
{
#ifdef DEBUG
   printf("In PayloadSearchInit()\n");
#endif

   /* whack a new node onto the list */
   NewNode(otn);

   /* set up the pattern buffer */
   ParsePattern(data, otn);

   /* link the plugin function in to the current OTN */
   AddOptFuncToList(CheckPatternMatch, otn);

#ifdef DEBUG
   printf("OTN function PatternMatch Added to rule!\n");
#endif
}



void PayloadSearchOffset(char *data, OptTreeNode *otn, int protocol)
{
   PatternMatchData *idx;

#ifdef DEBUG
   printf("In PayloadSearch()\n");
#endif

   idx = otn->ds_list[PLUGIN_PATTERN_MATCH];

   if(idx == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Please place \"content\" rules before depth or offset modifiers.\n", file_line);

      exit(1);
   }

   while(idx->next != NULL)
      idx = idx->next;

   while(isspace((int)*data)) data++;
      idx->offset = atoi(data);

#ifdef DEBUG
   printf("Pattern offset = %ld\n", idx->offset);
#endif

   return;
}



void PayloadSearchDepth(char *data, OptTreeNode *otn, int protocol)
{
   PatternMatchData *idx;

   idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

   if(idx == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Please place \"content\" rules before depth or offset modifiers.\n", file_line);

      exit(1);
   }

   while(idx->next != NULL)
      idx = idx->next;

   while(isspace((int)*data)) data++;
      idx->depth = atoi(data);

#ifdef DEBUG
   printf("Pattern offset = %ld\n", idx->offset);
#endif

   return;
}



void NewNode(OptTreeNode *otn)
{
   PatternMatchData *idx;

   idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

   if(idx == NULL)
   {
      if((otn->ds_list[PLUGIN_PATTERN_MATCH] = (PatternMatchData *) calloc(sizeof(PatternMatchData), sizeof(char))) == NULL)
      {
         fprintf(stderr, "ERROR => sp_pattern_match NewNode() calloc failed!\n");
         exit(1);
      }
   }
   else
   {
      idx = otn->ds_list[PLUGIN_PATTERN_MATCH];

      while(idx->next != NULL)
         idx = idx->next;

      if((idx->next = (PatternMatchData *) calloc(sizeof(PatternMatchData), sizeof(char))) == NULL)
      {
         fprintf(stderr, "ERROR => sp_pattern_match NewNode() calloc failed!\n");
         exit(1);
      }
   }
}



/****************************************************************************
 *
 * Function: ParsePattern(char *)
 *
 * Purpose: Process the application layer patterns and attach them to the
 *          appropriate rule.  My god this is ugly code.
 *
 * Arguments: rule => the pattern string 
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParsePattern(char *rule, OptTreeNode *otn)
{
   u_char tmp_buf[2048];
   /* got enough ptrs for you? */
   char *start_ptr;
   char *end_ptr;
   char *idx;
   char *dummy_idx;
   char *dummy_end;
   char hex_buf[9];
   u_int dummy_size = 0;
   u_int size;
   int hexmode = 0;
   int hexsize = 0;
   int pending = 0;
   int cnt = 0;
   int literal = 0;
   PatternMatchData *ds_idx;

   /* clear out the temp buffer */
   bzero(tmp_buf, 2048);

   /* find the start of the data */
   start_ptr = index(rule,'"');

   if(start_ptr == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Content data needs to be enclosed in quotation marks (\")!\n", file_line);
      exit(1);
   }

   /* move the start up from the beggining quotes */
   start_ptr++;
   
   /* find the end of the data */
   end_ptr = strrchr(start_ptr, '"');

   if(end_ptr == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Content data needs to be enclosed in quotation marks (\")!\n", file_line);
      exit(1);
   }

   /* set the end to be NULL */
   *end_ptr = 0;

   /* how big is it?? */
   size = end_ptr - start_ptr;
   
   /* uh, this shouldn't happen */
   if(size <= 0)
   {
      fprintf(stderr, "ERROR Line %d => Bad pattern length!\n", file_line);
      exit(1);
   }

   /* set all the pointers to the appropriate places... */
   idx = start_ptr;

   /* set the indexes into the temp buffer */
   dummy_idx = tmp_buf;
   dummy_end = (dummy_idx + size);

   /* why is this buffer so small? */
   bzero(hex_buf, 9);
   memset(hex_buf, '0', 8);

   /* BEGIN BAD JUJU..... */
   while(idx < end_ptr)
   {
#ifdef DEBUG
      printf("processing char: %c\n", *idx);
#endif
      switch(*idx)
      {
         case '|':
#ifdef DEBUG
               printf("Got bar... ");
#endif
               if(!literal)
               {
#ifdef DEBUG
                  printf("not in literal mode... ");
#endif
                  if(!hexmode)
                  {
#ifdef DEBUG
                     printf("Entering hexmode\n");
#endif
                     hexmode = 1;
                  }
                  else
                  {
#ifdef DEBUG
                     printf("Exiting hexmode\n");
#endif
                     hexmode = 0;
                  }

                  if(hexmode)
                     hexsize = 0;
               }
               else
               {
#ifdef DEBUG
                  printf("literal set, Clearing\n");
#endif
                  literal = 0;
                  tmp_buf[dummy_size] = start_ptr[cnt];
                  dummy_size++;
               }

               break;

         case '\\':
#ifdef DEBUG
               printf("Got literal char... ");
#endif
               if(!literal)
               {
#ifdef DEBUG
                  printf("Setting literal\n");
#endif
                  literal = 1;
               }
               else
               {
#ifdef DEBUG
                  printf("Clearing literal\n");
#endif
                  tmp_buf[dummy_size] = start_ptr[cnt];
                  literal = 0;
                  dummy_size++;
               }

               break;

         default:
               if(hexmode)
               {
                  if(isxdigit((int)*idx))
                  {
                     hexsize++;

                     if(!pending)
                     {
                        hex_buf[7] = *idx;
                        pending++;
                     }
                     else
                     {
                        hex_buf[8] = *idx;
                        pending--;

                        if(dummy_idx < dummy_end)
                        {
                           tmp_buf[dummy_size] = (u_long) strtol(hex_buf, (char **)NULL, 16);

                           dummy_size++;
                           bzero(hex_buf, 9);
                           memset(hex_buf, '0', 8);
                        }
                        else
                        {
                           fprintf(stderr, "ERROR => ParsePattern() dummy buffer overflow, make a smaller pattern please! (Max size = 2048)\n");
                           exit(1);
                        }
                     }
                  }
                  else
                  {
                     if(*idx != ' ')
                     {
                        fprintf(stderr, "ERROR Line %d => What is this \"%c\"(0x%X) doing in your binary buffer?  Valid hex values only please! (0x0 - 0xF) Position: %d\n", file_line, (char) *idx, (char) *idx, cnt);
                        exit(1);
                     }
                  }
               }
               else
               {
                  if(*idx >= 0x1F && *idx <= 0x7e)
                  {
                     if(dummy_idx < dummy_end)
                     {
                        tmp_buf[dummy_size] = start_ptr[cnt];
                        dummy_size++;
                     }
                     else
                     {
                        fprintf(stderr, "ERROR Line %d=> ParsePattern() dummy buffer overflow!\n", file_line);
                        exit(1);
                     }

                     if(literal)
                     {
                        literal = 0;
                     }
                  }
	          else
	          {
                     if(literal)
                     {
                        tmp_buf[dummy_size] = start_ptr[cnt];
                        dummy_size++;
#ifdef DEBUG
                        printf("Clearing literal\n");
#endif
                        literal = 0;
                     }
                     else
                     {
                        fprintf(stderr, "ERROR Line %d=> character value out of range, try a binary buffer dude\n", file_line);
	                exit(1);
                     }
	          }
               }
              
               break;
      }

      dummy_idx++;
      idx++;
      cnt++;
   }

   /* ...END BAD JUJU */

   ds_idx = (PatternMatchData *) otn->ds_list[PLUGIN_PATTERN_MATCH];

   while(ds_idx->next != NULL)
      ds_idx = ds_idx->next;

   if((ds_idx->pattern_buf=(char *)malloc(sizeof(char)*dummy_size))==NULL)
   {
      fprintf(stderr, "ERROR => ParsePattern() pattern_buf malloc filed!\n");
      exit(1);
   }

   memcpy(ds_idx->pattern_buf, tmp_buf, dummy_size);

   ds_idx->pattern_size = dummy_size;

   return;
}  




int CheckPatternMatch(Packet *p, struct _OptTreeNode *otn_idx, OptFpList *fp_list)
{
   int sub_depth;
   int found = 0;
   PatternMatchData *idx;
 
#ifdef DEBUG
   printf("CheckPatternMatch: ");
#endif

   idx = otn_idx->ds_list[PLUGIN_PATTERN_MATCH];

   while(idx != NULL)
   {
      if(idx->offset > p->dsize)
      {
#ifdef DEBUG
         printf("Initial offset larger than payload!\n");
#endif
         return 0;
      }
      else
      {
         /* do some tests to make sure we stay in bounds */      
         if((idx->depth + idx->offset) > p->dsize)
         {
            sub_depth = p->dsize - idx->offset;
      
            if(sub_depth >= idx->pattern_size)
            { 
#ifdef DEBUG
               printf("testing pattern: %s\n", idx->pattern_buf);
#endif
               found = mSearch((p->data+idx->offset), sub_depth,idx->pattern_buf, idx->pattern_size);

               if(!found)
               {
#ifdef DEBUG
                  printf("Pattern Match failed!\n");
#endif
                  return 0;
               }
            }
         }
         else
         {
#ifdef DEBUG
            printf("Testing pattern (lower section): %s\n", idx->pattern_buf);
#endif
            if(idx->depth)
            {
               found = mSearch((p->data+idx->offset), idx->depth, idx->pattern_buf, idx->pattern_size);
            }
            else
            {
               found = mSearch((p->data+idx->offset), p->dsize, idx->pattern_buf, idx->pattern_size);
            }

            if(!found)
            {
#ifdef DEBUG
               printf("Pattern Match failed!\n");
#endif
               return 0;
            }
         }
      }
   
      idx = idx->next;

#ifdef DEBUG
      printf("Stepping to next content keyword...\n");
#endif
   }

   if(found)
   {
#ifdef DEBUG
      printf("Pattern Match successful!\n");
#endif

      return fp_list->next->OptTestFunc(p, otn_idx, fp_list->next);

   } 
#ifdef DEBUG
   else
   {
      printf("Pattern match failed\n");
   }
#endif

   return 0;
}
