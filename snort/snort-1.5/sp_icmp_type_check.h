#ifndef __SP_ICMP_TYPE_CHECK_H__
#define __SP_ICMP_TYPE_CHECK_H__

#include "snort.h"


#define PLUGIN_ICMP_TYPE  3

typedef struct _IcmpTypeCheckData
{
  /* the icmp type number */
  int icmp_type;

} IcmpTypeCheckData;

void SetupIcmpTypeCheck();
void IcmpTypeCheckInit(char *, OptTreeNode *, int);
void ParseIcmpType(char *, OptTreeNode *);
int IcmpTypeCheck(Packet *, struct _OptTreeNode *, OptFpList *);

#endif  /* __SP_ICMP_TYPE_CHECK_H__ */
