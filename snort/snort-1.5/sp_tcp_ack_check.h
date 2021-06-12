#ifndef __SP_TCP_ACK_CHECK_H__
#define __SP_TCP_ACK_CHECK_H__

#include "snort.h"

#define PLUGIN_TCP_ACK_CHECK  9

typedef struct _TcpAckCheckData
{
   u_long tcp_ack;

} TcpAckCheckData;

void TcpAckCheckInit(char *, OptTreeNode *, int);
void SetupTcpAckCheck();
void ParseTcpAck(char *, OptTreeNode *);
int CheckTcpAckEq(Packet *, struct _OptTreeNode *, OptFpList *);

#endif  /* __SP_TCP_ACK_CHECK_H__ */
