#ifndef __SP_TCP_SEQ_CHECK_H__
#define __SP_TCP_SEQ_CHECK_H__

#include "snort.h"

#define PLUGIN_TCP_SEQ_CHECK  10

typedef struct _TcpSeqCheckData
{
   u_long tcp_seq;

} TcpSeqCheckData;

void TcpSeqCheckInit(char *, OptTreeNode *, int);
void SetupTcpSeqCheck();
void ParseTcpSeq(char *, OptTreeNode *);
int CheckTcpSeqEq(Packet *, struct _OptTreeNode *, OptFpList *);

#endif  /* __SP_TCP_SEQ_CHECK_H__ */
