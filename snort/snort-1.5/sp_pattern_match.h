#include "snort.h"
#ifndef __SP_PATTERN_MATCH_H__
#define __SP_PATTERN_MATCH_H__


#define PLUGIN_PATTERN_MATCH   1

typedef struct _PatternMatchData
{
   int offset;             /* pattern search start offset */
   int depth;              /* pattern search depth */
   u_int pattern_size;     /* size of app layer pattern */
   char *pattern_buf;      /* app layer pattern to match on */ 
   struct _PatternMatchData *next; /* ptr to next match struct */

} PatternMatchData;

void PayloadSearchInit(char *, OptTreeNode *, int);
void SetupPatternMatch();
void ParsePattern(char *, OptTreeNode *);
int CheckPatternMatch(Packet *, struct _OptTreeNode *, OptFpList *);
void PayloadSearchOffset(char *, OptTreeNode *, int);
void PayloadSearchDepth(char *, OptTreeNode *, int);
void NewNode(OptTreeNode *);


#endif
