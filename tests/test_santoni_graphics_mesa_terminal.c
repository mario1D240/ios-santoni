#include "macros.h"
#include <stdlib.h>
static volatile unsigned noted;
static __attribute__((noinline)) void record(unsigned mode) { noted=mode; }
static __attribute__((noinline)) unsigned classify(unsigned mode)
{
   if (mode>1) {
      record(mode);
      unreachable("Unsupported explicit IO variable mode");
   }
   return 91+mode;
}
int main(int argc,char **argv)
{
   if(argc!=2)return 2;
   unsigned mode=(unsigned)strtoul(argv[1],NULL,10);
   unsigned value=classify(mode);
   printf("RETURN mode=%u value=%u noted=%u\n",mode,value,noted);
   return value==91+mode?0:3;
}
