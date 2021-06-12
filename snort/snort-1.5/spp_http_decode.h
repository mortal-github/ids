#include "snort.h"

#ifndef __SPP_HTTP_DECODE_H__
#define __SPP_HTTP_DECODE_H__

/* this is where we keep the list of ports that this process is 
   going to be applied to */
typedef struct _PortList
{
   int ports[32];   /* 32 is kind of arbitrary */

   int num_entries;

} PortList;


void SetupHttpDecode();
void HttpDecodeInit(u_char *);
void SetPorts(char *);
void PreprocUrlDecode(Packet *);
char x2c(char *);


#endif  /* __SPP_HTTP_DECODE_H__ */
