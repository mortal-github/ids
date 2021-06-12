#ifndef __SP_TTL_CHECK_H__
#define __SP_TTL_CHECK_H__

#include "snort.h"

#define PLUGIN_TTL_CHECK  5

typedef struct _TtlCheckData
{
   int ttl;

} TtlCheckData;

void TtlCheckInit(char *, OptTreeNode *, int);
void SetupTtlCheck();
void ParseTtl(char *, OptTreeNode *);
int CheckTtlEq(Packet *, struct _OptTreeNode *, OptFpList *);

#endif  /* __SP_TTL_CHECK_H__ */
