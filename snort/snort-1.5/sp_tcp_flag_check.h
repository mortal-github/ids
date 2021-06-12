#ifndef __SP_TCP_FLAG_CHECK_H__
#define __SP_TCP_FLAG_CHECK_H__

#include "snort.h"

#define PLUGIN_TCP_FLAG_CHECK   2

typedef struct _TCPFlagCheckData
{
   u_char tcp_flags; /* ptr to next match struct */

} TCPFlagCheckData;

void TCPFlagCheckInit(char *, OptTreeNode *, int);
void SetupTCPFlagCheck();
void ParseFlags(char *, OptTreeNode *);
int CheckTcpFlagsEq(Packet *, struct _OptTreeNode *, OptFpList *);


#endif
