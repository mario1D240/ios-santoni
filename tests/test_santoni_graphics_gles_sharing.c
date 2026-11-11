/* Actual frontend functions and pinned declarations; Mesa/transport modeled. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bool fail_calloc,fail_context;
static void *fixture_calloc(size_t n,size_t bytes)
{if(fail_calloc){fail_calloc=false;return NULL;}return calloc(n,bytes);}
#define calloc fixture_calloc
#include "gles_lifecycle.h"
#undef calloc
struct model_group {struct pipe_screen screen;struct pipe_frontend_screen *frontend;
    unsigned live,created;int fd;bool pipe,bookkeeping;};
struct st_context {struct model_group *group;struct st_context *shared;bool live;};
static struct model_group groups[4];
static struct st_context contexts[8],foreign;
static struct st_context *current;
static unsigned ng,nc,closed,screen_destroyed,contexts_destroyed;
int sgfx_drm_open(void){assert(ng<4);unsigned i=ng++;return groups[i].fd=100+(int)i;}
int sgfx_drm_close(int fd)
{for(unsigned i=0;i<ng;i++)if(groups[i].fd==fd){assert(!groups[i].pipe && !groups[i].bookkeeping && !groups[i].live);closed++;return 0;}assert(false);return -1;}
bool sgfx_drm_status(int fd,uint32_t *submitted,uint32_t *completed)
{(void)fd;*submitted=*completed=1;return true;}
void driParseOptionInfo(driOptionCache *info,const driOptionDescription *options,unsigned n)
{assert(info && options && n);info->tableSize=7;}
void driDestroyOptionInfo(driOptionCache *info){assert(info->tableSize==7);}
void driDestroyOptionCache(driOptionCache *options){assert(options);}
static struct model_group *for_screen(struct pipe_screen *screen)
{for(unsigned i=0;i<ng;i++)if(&groups[i].screen==screen)return &groups[i];assert(false);return NULL;}
static void destroy_pipe(struct pipe_screen *screen)
{struct model_group *g=for_screen(screen);assert(g->pipe && !g->bookkeeping && !g->live);g->pipe=false;screen_destroyed++;}
struct pipe_screen *fd_drm_screen_create_renderonly(int fd,struct renderonly *ro,const struct pipe_screen_config *config)
{assert(!ro && config && config->options_info->tableSize==7);for(unsigned i=0;i<ng;i++)if(groups[i].fd==fd){groups[i].pipe=true;groups[i].screen.destroy=destroy_pipe;return &groups[i].screen;}assert(false);return NULL;}
struct st_context *st_api_create_context(struct pipe_frontend_screen *frontend,const struct st_context_attribs *attrs,
    enum st_context_error *error,struct st_context *shared)
{
    assert(nc<8 && attrs->profile==API_OPENGLES2 && (attrs->major==2 || attrs->major==3) && !attrs->minor);
    struct model_group *g=for_screen(frontend->screen);assert(g->pipe && *error==ST_CONTEXT_SUCCESS);
    assert(frontend->get_param && frontend->get_param(frontend,ST_MANAGER_BROKEN_INVALIDATE)==0);
    if(shared){assert(shared->live && shared->group==g && g->frontend==frontend && g->bookkeeping);}
    else{assert(!g->frontend);g->frontend=frontend;g->bookkeeping=true;frontend->st_screen=(struct st_screen *)g;}
    if(fail_context){fail_context=false;*error=ST_CONTEXT_ERROR_NO_MEMORY;return NULL;}
    struct st_context *c=&contexts[nc++];*c=(struct st_context){g,shared,true};g->live++;g->created++;return c;
}
bool st_api_make_current(struct st_context *c,struct pipe_frontend_drawable *draw,struct pipe_frontend_drawable *read)
{assert(!draw && !read && (!c || c->live));current=c;return true;}
struct st_context *st_api_get_current(void){return current;}
void st_destroy_context(struct st_context *c)
{assert(c->live && c!=current && c->group->pipe && c->group->bookkeeping);c->live=false;c->group->live--;contexts_destroyed++;}
void st_screen_destroy(struct pipe_frontend_screen *frontend)
{struct model_group *g=(void *)frontend->st_screen;assert(g && !g->live && g->bookkeeping && g->pipe);g->bookkeeping=false;frontend->st_screen=NULL;}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<11);
    assert(!unsetenv("MESA_EXTENSION_OVERRIDE"));
    if(test==8) {
        assert(!setenv("MESA_EXTENSION_OVERRIDE","GL_APPLE_tile_order_rot",1));
        assert(!sgfx_gles_create_api(3) && !sgfx_gles_create_shared_api(2,NULL));
        assert(!ng && !nc && !closed);return 0;
    }
    if(test==9)assert(!setenv("MESA_EXTENSION_OVERRIDE","",1));
    struct sgfx_gles_context *root=sgfx_gles_create_api(3);assert(root && root->references==1);
    if(test==10) {
        assert(!setenv("MESA_EXTENSION_OVERRIDE","GL_EXT_shader_framebuffer_fetch",1));
        assert(!sgfx_gles_create_shared_api(2,NULL) && ng==1 && nc==1 && contexts[0].live);
        assert(!unsetenv("MESA_EXTENSION_OVERRIDE"));sgfx_gles_destroy(root);
    }else if(test==3 || test==4 || test==5){
        unsigned before=root->references;
        if(test==3)fail_calloc=true;
        if(test==4)fail_context=true;
        if(test==5){root->references=UINT32_MAX;assert(!sgfx_gles_retain(root));}
        assert(!sgfx_gles_create_shared_api(2,root));
        assert(root->references==(test==5?UINT32_MAX:before) && contexts[0].live && ng==1 && nc==1);
        root->references=before;assert(!sgfx_gles_create_shared_api(1,root));sgfx_gles_destroy(root);
    }else if(test==6){
        struct sgfx_gles_context *independent=sgfx_gles_create_shared_api(2,NULL);assert(independent && ng==2 && nc==2);
        assert(contexts[0].group!=contexts[1].group && !contexts[1].shared);
        sgfx_gles_destroy(root);assert(contexts[1].live);sgfx_gles_destroy(independent);
    }else{
        struct sgfx_gles_context *child=sgfx_gles_create_shared_api(2,root);assert(child && root->references==2 && ng==1 && nc==2);
        assert(child->fd==root->fd && contexts[1].shared==&contexts[0]);
        if(test==1){
            struct sgfx_gles_context *grandchild=sgfx_gles_create_shared_api(3,child);
            assert(grandchild && grandchild->screen_owner==root && contexts[2].shared==&contexts[1]);
            sgfx_gles_destroy(child);assert(!contexts[1].live && contexts[0].live && contexts[2].live);
            sgfx_gles_destroy(root);assert(contexts[0].live && contexts[2].live);sgfx_gles_destroy(grandchild);
        }else if(test==2){
            assert(sgfx_gles_retain(root));sgfx_gles_destroy(root);sgfx_gles_destroy(child);
            assert(contexts[0].live && !contexts[1].live && !closed);sgfx_gles_destroy(root);
        }else if(test==7){
            assert(sgfx_gles_retain(child));foreign.live=true;current=&foreign;
            sgfx_gles_destroy(root);sgfx_gles_destroy(child);assert(contexts[1].live && current==&foreign);
            sgfx_gles_destroy(child);assert(current==&foreign);
        }else{
            assert(sgfx_gles_current(child));sgfx_gles_destroy(root);assert(current==&contexts[1] && contexts[0].live);
            sgfx_gles_destroy(child);assert(!current);
        }
    }
    assert(closed==ng && screen_destroyed==ng && contexts_destroyed==nc);
    assert(!sgfx_gles_retain(NULL));sgfx_gles_destroy(NULL);
    printf("PASS shared frontend case=%u contexts=%u screens=%u; Mesa/transport modeled\n",test,nc,ng);
    return 0;
}
