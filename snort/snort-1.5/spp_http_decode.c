/* spp_http_decode 
 * 
 * Purpose:
 *
 * This preprocessor normalizes HTTP requests from remote machines by
 * converting any %XX character substitutions to their ASCII equivalent.
 * This is very useful for doing things like defeating hostile attackers
 * trying to stealth themselves from IDSs by mixing these substitutions 
 * in with the request.
 *
 * Arguments:
 *   
 * This plugin takes a list of integers representing the TCP ports that the
 * user is interested in having normalized
 *
 * Effect:
 *
 * Changes the data in the packet payload to a plain ASCII representation 
 * and changes p->dsize to reflect the new (smaller) payload size.
 *
 * Comments:
 *
 * It could be interesting to generate an alert based on the number of
 * characters converted for a single packet, through some sort of threshold
 * setting.
 *
 */
#include "spp_http_decode.h"

extern char *file_name;
extern int file_line;

/* Instantiate the list of ports we're going to watch */
PortList HttpDecodePorts;

/*
 * Function: SetupHttpDecode()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupHttpDecode()
{
   /* link the preprocessor keyword to the init function in 
      the preproc list */
   RegisterPreprocessor("http_decode", HttpDecodeInit);

#ifdef DEBUG
   printf("Preprocessor: HttpDecode in setup...\n");
#endif
}


/*
 * Function: HttpDecodeInit(u_char *)
 *
 * Purpose: Processes the args sent to the preprocessor, sets up the
 *          port list, links the processing function into the preproc
 *          function list
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void HttpDecodeInit(u_char *args)
{
#ifdef DEBUG
   printf("Preprocessor: HttpDecode Initialized\n");
#endif

   /* parse the argument list into a list of ports to normalize */
   SetPorts(args);

   /* Set the preprocessor function into the function list */
   AddFuncToPreprocList(PreprocUrlDecode);
}



/*
 * Function: SetPorts(char *)
 *
 * Purpose: Reads the list of port numbers from the argument string and 
 *          parses them into the port list data struct
 *
 * Arguments: portlist => argument list
 *
 * Returns: void function
 *
 */
void SetPorts(char *portlist)
{
   char **toks;
   int num_toks;
   int num_ports = 0;

   if(portlist == NULL)
   {
      fprintf(stderr, "ERROR %s (%d)=> No arguments to http_decode preprocessor!\n", file_name, file_line);
      exit(1);
   }

   /* tokenize the argument list */
   toks = mSplit(portlist, " ", 31, &num_toks, '\\');

   /* convert the tokens and place them into the port list */
   for(num_ports = 0; num_ports < num_toks; num_ports++)
   {
      HttpDecodePorts.ports[num_ports] = atoi(toks[num_ports]);
   }   

   HttpDecodePorts.num_entries = num_ports;

#ifdef DEBUG
   printf("Decoding HTTP on %d ports: ", HttpDecodePorts.num_entries);

   for(num_ports = 0; num_ports < HttpDecodePorts.num_entries; num_ports++)
   {
      printf("%d ", HttpDecodePorts.ports[num_ports]);
   }

   printf("\n");
#endif

}


/*
 * Function: PreprocUrlDecode(Packet *)
 *
 * Purpose: Inspects the packet's payload for "Escaped" characters and 
 *          converts them back to their ASCII values.  This function
 *          is based on the NCSA code and was contributed by Michael Henry!
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
void PreprocUrlDecode(Packet *p)
{
   register u_short x,y;
   char *url;
   u_short psize;
   int i;

   /* check the port against the decode port list */
   for(i = 0; i < HttpDecodePorts.num_entries; i++)
   {
      if(HttpDecodePorts.ports[i] == p->dp)
      { 
        /* on match, normalize the data */
#ifdef DEBUG
         printf("Got HTTP traffic!\n");
#endif

         url = (char *) p->data;
         psize = (u_short) p->dsize;

         for (x=0,y=0; y < psize ; ++x,++y) 
         {
            if((url[x] = url[y]) == '%') 
            {
               url[x] = x2c(&url[y+1]);
               y+=2;
            }
         }

         /* set the payload size to reflect the new size */ 
         p->dsize = x;

#ifdef DEBUG
         printf("converted data: %s\n", url);
         PrintNetData(stdout, url, x);
#endif

         return;
      }
   }
}




/*
 * Function: x2c(char *)
 *
 * Purpose: Performs the actual value->character conversion on the data
 *
 * Arguments: what => the character in question
 *
 * Returns: The converted character
 *
 */
char x2c(char *what)
{
  register char digit;

  digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));

  /* mult by 16... */
  digit = digit << 4;

  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));

  return(digit);
}
