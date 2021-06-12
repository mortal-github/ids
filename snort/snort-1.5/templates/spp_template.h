/* Snort Preprocessor Plugin Header File Template */

/* This file gets included in plugbase.h when it is integrated into the rest 
 * of the program.  Sometime in The Future, I'll whip up a bad ass Perl script
 * to handle automatically loading all the required info into the plugbase.*
 * files.
 */
#include "snort.h"

#ifndef __SPP_TEMPLATE_H__
#define __SPP_TEMPLATE_H__

typedef struct _TemplateData
{
  /* your data goes here! */
} TemplateData;

/* list of function prototypes for this preprocessor */
void SetupTemplate();
void TemplateInit(u_char *);
void ParseTemplateArgs(char *);
void PreprocFunction(Packet *);


#endif  /* __SPP_TEMPLATE_H__ */
