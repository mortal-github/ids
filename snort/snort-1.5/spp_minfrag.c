#include "spp_http_decode.h"


void SetupMinfrag()
{
   RegisterPreprocessor("minfrag", MinfragInit);

#ifdef DEBUG
   printf("Preprocessor: Minfrag Initialized\n");
#endif
}


void MinfragInit(u_char *args)
{
#ifdef DEBUG
   printf("Preprocessor: Minfrag initializing\n");
#endif

   while(isspace(*args)) args++;

   minfrag = atoi(args);

#ifdef DEBUG
   printf("Setting Minimum Fragment Size: %d bytes\n", minfrag);
#endif

   AddFuncToPreprocList(CheckMinfrag);
}



void CheckMinfrag(Packet *p)
{
   if(!p->frag_flag)
   {
#ifdef DEBUG
      printf("p->frag_flag = %d\n", p->frag_flag);
#endif
      return;
   }

#ifdef DEBUG
   printf("p->frag_offset = 0x%04X\n", p->frag_offset);
#endif

   if(p->frag_offset == 0)
   {
      if(p->dsize <= minfrag)
      {
#ifdef DEBUG
         printf("datasize = %d   minfrag = %d  \n", p->dsize, minfrag);
         printf("Calling AlertFunc & LogFunc!\n");
#endif
         (*AlertFunc)(p, MINFRAG_ALERT_MESSAGE);
         (*LogFunc)(p);
      }
   }
}


