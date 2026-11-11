/* Actual readiness function; clock, sleep and status responses modeled. */
#include "santoni_drm.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
static unsigned test_case,status_calls,clock_calls,sleeps;
static uint64_t clock_ns=1000000000ull;
int clock_gettime(clockid_t clock,struct timespec *out)
{
    assert(clock==CLOCK_MONOTONIC && out);clock_calls++;
    if(test_case==9)return -1;
    if(test_case==10 && clock_calls==3)clock_ns--;
    out->tv_sec=(time_t)(clock_ns/1000000000ull);out->tv_nsec=(long)(clock_ns%1000000000ull);
    if(test_case==11)out->tv_sec=-1;
    if(test_case==12)out->tv_nsec=-1;
    if(test_case==13)out->tv_nsec=1000000000;
    if(test_case==14)out->tv_sec=18446744060ll;
    if(test_case==15)out->tv_sec=20000000000ll;
    return 0;
}
int nanosleep(const struct timespec *in,struct timespec *remaining)
{
    assert(in && !in->tv_sec && in->tv_nsec==100000000 && !remaining);sleeps++;
    if(test_case==16){errno=EINTR;return -1;}
    if(test_case!=17)clock_ns+=100000000ull;
    return 0;
}
int sgfx_ios_renderer_status(uint64_t out[5])
{
    assert(out && !out[0] && !out[1] && !out[2] && !out[3] && !out[4]);status_calls++;
    out[0]=1;out[1]=1;out[2]=1;
    if(test_case==1 && status_calls<=3)out[2]=0;
    if(test_case==2 && status_calls<=2)return -ENODEV;
    if(test_case==3)out[1]=0;
    if(test_case==4)out[3]=1;
    if(test_case==5){out[3]=1;out[4]=1;}
    if(test_case==6)return -EACCES;
    if(test_case==7)return -EIO;
    if(test_case==8){clock_ns+=60000000000ull;out[2]=1;}
    if(test_case==16 || test_case==17 || test_case==18)out[2]=0;
    if(test_case==19)out[2]=2;
    if(test_case==20)out[0]=2;
    if(test_case==21)out[1]=2;
    if(test_case==22)out[4]=1;
    if(test_case==23)return -EPROTO;
    if(test_case==24 && status_calls<=599)out[2]=0;
    if(test_case==25){clock_ns+=60000000001ull;return -ENODEV;}
    if(test_case==26 && status_calls<=410)out[2]=0;
    if(test_case==27 && status_calls<=410)return -ENODEV;
    if(test_case==28)clock_ns+=59999999999ull;
    return 0;
}
int main(int argc,char **argv)
{
    assert(argc==2);test_case=(unsigned)strtoul(argv[1],NULL,10);assert(test_case<29);
    bool result=sgfx_ios_renderer_wait();
    assert(result==(test_case==0 || test_case==1 || test_case==2 || test_case==24 || test_case>=26));
    if(test_case==0)assert(status_calls==1 && !sleeps);
    if(test_case==1)assert(status_calls==4 && sleeps==3);
    if(test_case==2)assert(status_calls==3 && sleeps==2);
    if((test_case>=3 && test_case<=8) || (test_case>=19 && test_case<=23) || test_case==25)assert(status_calls==1 && !sleeps);
    if((test_case>=11 && test_case<=15) || test_case==9)assert(!status_calls && !sleeps);
    if(test_case==10)assert(status_calls==1 && !sleeps);
    if(test_case==16)assert(status_calls==1 && sleeps==1);
    if(test_case==17 || test_case==18)assert(status_calls==600 && sleeps==600);
    if(test_case==24)assert(status_calls==600 && sleeps==599);
    if(test_case==26 || test_case==27)assert(status_calls==411 && sleeps==410);
    if(test_case==28)assert(status_calls==1 && !sleeps);
    return 0;
}
