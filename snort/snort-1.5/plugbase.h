#ifndef __PLUGBASE_H__
#define __PLUGBASE_H__

#include "rules.h"
#include "sp_pattern_match.h"
#include "sp_tcp_flag_check.h"
#include "sp_icmp_type_check.h"
#include "sp_icmp_code_check.h"
#include "sp_ttl_check.h"
#include "sp_ip_id_check.h"
#include "sp_tcp_ack_check.h"
#include "sp_tcp_seq_check.h"
#include "sp_dsize_check.h"
#include "sp_ipoption_check.h"

#include "spp_http_decode.h"
#include "spp_minfrag.h"


typedef struct _KeywordXlate
{
   char *keyword;
   void (*func)(char *, OptTreeNode *, int);
} KeywordXlate;



typedef struct _KeywordXlateList
{
   KeywordXlate entry;
   struct _KeywordXlateList *next;
} KeywordXlateList;


/* preprocessor data struct */
typedef struct _PreprocessKeywordNode
{
   char *keyword;
   void (*func)(char *);

} PreprocessKeywordNode;




typedef struct _PreprocessKeywordList
{
   PreprocessKeywordNode entry;
   struct _PreprocessKeywordList *next;

} PreprocessKeywordList;




typedef struct _PreprocessFuncNode
{
   void (*func)(Packet *);
   struct _PreprocessFuncNode *next;

} PreprocessFuncNode;


void InitPlugIns();
void InitPreprocessors();
void RegisterPlugin(char *, void (*func)(char *, OptTreeNode *, int));
void DumpPlugIns();
void RegisterPreprocessor(char *, void (*func)(u_char *));
void DumpPreprocessors();


#endif

