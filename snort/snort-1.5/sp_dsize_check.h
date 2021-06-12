#ifndef __SP_DSIZE_CHECK_H__
#define __SP_DSIZE_CHECK_H__

#include "snort.h"

#define PLUGIN_DSIZE_CHECK  7

#define EQ                   0
#define GT                   1
#define LT                   2

typedef struct _DsizeCheckData
{
   int dsize;

} DsizeCheckData;

void DsizeCheckInit(char *, OptTreeNode *, int);
void SetupDsizeCheck();
void ParseDsize(char *, OptTreeNode *);
int CheckDsizeEq(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckDsizeGT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckDsizeLT(Packet *, struct _OptTreeNode *, OptFpList *);

#endif  /* __SP_DSIZE_CHECK_H__ */
