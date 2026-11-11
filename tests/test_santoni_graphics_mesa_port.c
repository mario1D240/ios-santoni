/* Factory body and declarations come from the mechanically ported Mesa tree. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "mesa_factory.h"
struct pipe_screen {unsigned marker;};
struct pipe_screen_config {unsigned marker;};
struct renderonly {unsigned marker;};
static struct pipe_screen screen;
static int expected_fd;
static const struct pipe_screen_config *expected_config;
static struct renderonly *expected_ro;
static unsigned calls;
struct pipe_screen *fd_screen_create(int fd,const struct pipe_screen_config *config,struct renderonly *ro)
{
    assert(fd==expected_fd && config==expected_config && ro==expected_ro);
    calls++;return &screen;
}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<4);
    struct pipe_screen_config config={17};struct renderonly ro={29};
    expected_fd=731;expected_config=test&1?NULL:&config;expected_ro=test&2?NULL:&ro;
    assert(fd_drm_screen_create_renderonly(expected_fd,expected_ro,expected_config)==&screen && calls==1);
    printf("PASS actual Mesa factory arguments case=%u; no GPU execution\n",test);return 0;
}
