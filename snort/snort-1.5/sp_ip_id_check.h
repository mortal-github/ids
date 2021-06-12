#ifndef __SP_IP_ID_CHECK_H__
#define __SP_IP_ID_CHECK_H__

#include "snort.h"

#define PLUGIN_IP_ID_CHECK  8

typedef struct _IpIdData
{
   u_long ip_id;

} IpIdData;

void IpIdCheckInit(char *, OptTreeNode *, int);
void SetupIpIdCheck();
void ParseIpId(char *, OptTreeNode *);
int IpIdCheckEq(Packet *, struct _OptTreeNode *, OptFpList *);

#endif  /* __SP_IP_ID_CHECK_H__ */
