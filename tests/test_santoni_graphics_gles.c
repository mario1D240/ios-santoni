/* Actual frontend lifecycle, pinned Mesa declarations, modeled dependencies.
 * No shader compiler, GPU submission, pixels or phone response is modeled as
 * proof here. Context creation deliberately calls the required Mesa callback. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned test;
static char events[64];
static unsigned count;
static void event(char value) {assert(count+1<sizeof(events));events[count++]=value;}
static void *test_calloc(size_t n,size_t size)
{event('A');return test==5?NULL:calloc(n,size);}
#define calloc test_calloc
#include "gles_lifecycle.h"
#undef calloc
struct st_context {unsigned alive;};
static struct st_context context,other={1};
static struct st_context *current;
static struct pipe_frontend_screen *frontend;
static struct pipe_screen screen;
static unsigned pipe_alive,bookkeeping_alive;
int sgfx_drm_open(void) {event('O');return test==4?-1:73;}
int sgfx_drm_close(int fd)
{assert(fd==73 && !context.alive && !pipe_alive && !bookkeeping_alive);event('F');return 0;}
bool sgfx_drm_status(int fd,uint32_t *submitted,uint32_t *completed)
{assert(fd==73);*submitted=9;*completed=8;return test!=12;}
void driParseOptionInfo(driOptionCache *info,const driOptionDescription *descriptions,unsigned n)
{assert(info && descriptions && n);event('I');info->tableSize=7;}
void driDestroyOptionCache(driOptionCache *options)
{assert(options && !context.alive && !pipe_alive && !bookkeeping_alive);event('K');}
void driDestroyOptionInfo(driOptionCache *info)
{assert(info->tableSize==7 && !pipe_alive && !bookkeeping_alive);event('N');}
static void destroy_pipe(struct pipe_screen *value)
{assert(value==&screen && pipe_alive && !bookkeeping_alive && !context.alive);event('X');pipe_alive=0;}
struct pipe_screen *fd_drm_screen_create_renderonly(int fd,struct renderonly *ro,const struct pipe_screen_config *config)
{
    assert(fd==73 && !ro && config && config->options && config->options_info->tableSize==7);
    assert(!strcmp(getenv("FD_MESA_DEBUG"),"sysmem,notile,noubwc,nofp16,inorder,noindirect"));
    assert(!strcmp(getenv("IR3_SHADER_DEBUG"),"nofp16"));event('P');
    if(test==6)return NULL;
    screen.destroy=destroy_pipe;pipe_alive=1;return &screen;
}
struct st_context *st_api_create_context(struct pipe_frontend_screen *value,const struct st_context_attribs *attribs,
    enum st_context_error *error,struct st_context *shared)
{
    assert(value && value->screen==&screen && pipe_alive && !shared && error && *error==ST_CONTEXT_SUCCESS);
    assert(attribs->profile==API_OPENGLES2 && attribs->major==(test==1?3:2) && !attribs->minor);
    assert(!attribs->flags && !attribs->context_flags);
    assert(value->get_param && value->get_param(value,ST_MANAGER_BROKEN_INVALIDATE)==0);
    event('C');frontend=value;bookkeeping_alive=1;value->st_screen=(struct st_screen *)&bookkeeping_alive;
    if(test==7) {*error=ST_CONTEXT_ERROR_NO_MEMORY;return NULL;}
    context.alive=1;return &context;
}
bool st_api_make_current(struct st_context *value,struct pipe_frontend_drawable *draw,struct pipe_frontend_drawable *read)
{
    assert(!draw && !read);event('M');
    if(test==10 && value)return false;
    assert(!value || value->alive);current=value;return true;
}
struct st_context *st_api_get_current(void) {return current;}
void st_destroy_context(struct st_context *value)
{assert(value==&context && context.alive && pipe_alive && bookkeeping_alive && current!=value);event('D');context.alive=0;}
void st_screen_destroy(struct pipe_frontend_screen *value)
{
    assert(value && !context.alive);event('S');
    if(bookkeeping_alive) {assert(value==frontend && pipe_alive && value->st_screen);bookkeeping_alive=0;value->st_screen=NULL;}
    else assert(!value->st_screen);
}
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<14);
    current=&other;
    if(test==11 || test==13) {
        uint32_t submitted=0,completed=0;
        assert(!sgfx_gles_api(NULL) && !sgfx_gles_status(NULL,&submitted,&completed));
        sgfx_gles_destroy(NULL);assert(!count && current==&other);
        if(test==11) {assert(sgfx_gles_current(NULL) && !current && !strcmp(events,"M"));}
        return 0;
    }
    struct sgfx_gles_context *value=test==0?sgfx_gles_create():sgfx_gles_create_api(test==1?3:test==2?0:test==3?4:2);
    if(test>=2 && test<=7) {
        const char *expected[]={"","","","","O","OAF","OAIPSKNF","OAIPCSXKNF"};
        assert(!value && current==&other && !strcmp(events,expected[test]));return 0;
    }
    assert(value && sgfx_gles_api(value)==(test==1?3:2) && !strcmp(events,"OAIPC"));
    uint32_t submitted=0,completed=0;
    assert(!sgfx_gles_status(value,NULL,&completed) && !sgfx_gles_status(value,&submitted,NULL));
    assert(sgfx_gles_status(value,&submitted,&completed)==(test!=12) && submitted==9 && completed==8);
    if(test==8 || test==10) {
        assert(sgfx_gles_current(value)==(test==8));assert(current==(test==8?&context:&other));
    }
    sgfx_gles_destroy(value);
    assert(current==(test==8?NULL:&other) && !pipe_alive && !bookkeeping_alive && !context.alive);
    assert(!strcmp(events,test==8?"OAIPCMMDSXKNF":test==10?"OAIPCMDSXKNF":"OAIPCDSXKNF"));
    puts("PASS actual GLES lifecycle; Mesa/transport dependencies modeled");return 0;
}
