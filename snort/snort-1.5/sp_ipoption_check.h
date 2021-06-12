#ifndef __SP_IPOPTION_CHECK_H__
#define __SP_IPOPTION_CHECK_H__

#include "snort.h"

#define PLUGIN_IPOPTION_CHECK  11

typedef struct _IpOptionData
{
  u_char ip_option;

} IpOptionData;

void SetupIpOptionCheck();
void IpOptionInit(char *, OptTreeNode *, int);
void ParseIpOptionData(char *, OptTreeNode *);
int CheckIpOptions(Packet *, struct _OptTreeNode *, OptFpList *);

#endif  /* __SP_IPOPTION_CHECK_H__ */
