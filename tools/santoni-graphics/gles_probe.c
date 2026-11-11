#include "gles.h"
#include <stdio.h>
#include <string.h>
int main(int argc,char **argv)
{
    if(argc!=2 || strcmp(argv[1],"--gles-readback-proof")) {
        fprintf(stderr,"usage: %s --gles-readback-proof\n",argv[0]);return 2;
    }
    return sgfx_gles_readback_proof()?0:1;
}
