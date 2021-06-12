#ifndef __SP_ICMP_CODE_CHECK_H__
#define __SP_ICMP_CODE_CHECK_H__

#include "snort.h"

#define PLUGIN_ICMP_CODE  4

typedef struct _IcmpCodeCheckData
{
  /* the icmp code number */
  int icmp_code;

} IcmpCodeCheckData;

void SetupIcmpCodeCheck();
void IcmpCodeCheckInit(char *, OptTreeNode *, int);
void ParseIcmpCode(char *, OptTreeNode *);
int IcmpCodeCheck(Packet *, struct _OptTreeNode *, OptFpList *);

#endif  /* __SP_ICMP_CODE_CHECK_H__ */
