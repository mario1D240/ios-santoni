/* Actual capture dimension parser; host only, no Mesa/GPU execution. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "capture_dimensions.h"
int main(int argc,char **argv)
{
    static const char *values[]={NULL,"","0","64","720","1280","4096","4097","-1","+64"," 64","0x40","64garbage","18446744073709551616"};
    static const unsigned expected[]={64,0,0,64,720,1280,4096,0,0,0,0,0,0,0};
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<sizeof(expected)/sizeof(expected[0]));
    if(values[test])assert(!setenv("SANTONI_CAPTURE_WIDTH",values[test],1));else assert(!unsetenv("SANTONI_CAPTURE_WIDTH"));
    assert(dimension("SANTONI_CAPTURE_WIDTH")==expected[test]);
    puts("PASS actual bounded decimal capture dimension; no GPU execution");return 0;
}
