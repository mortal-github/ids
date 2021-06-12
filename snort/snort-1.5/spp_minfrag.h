#ifndef __SPP_MINFRAG_H__
#define __SPP_MINFRAG_H__

#include "snort.h"

#define MINFRAG_ALERT_MESSAGE "Tiny Fragments - Possible Hostile Activity"

int minfrag;

void SetupMinfrag();
void MinfragInit(u_char *);
void CheckMinfrag(Packet *);


#endif  /* __SPP_MINFRAG_H__ */
