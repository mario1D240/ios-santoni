/* Separate, explicitly selected backboardd loader. The Mesa/EAGL library has
 * no constructor. Its content-addressed path is supplied by the audited build;
 * kernel renderer admission independently checks the task/executable identity. */
#include "ui_loader_config.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#ifndef RTLD_FIRST
#error "Darwin RTLD_FIRST is required for the exact-image install entry"
#endif
static pthread_mutex_t loader_lock=PTHREAD_MUTEX_INITIALIZER;
static bool attempted,result;
static void *framework_handle,*library_handle;
/* Keep the exact path as a string literal so Darwin emits the readonly
 * __cstring declaration required by the loader/image binding audit. */
static const char *const library_path=SANTONI_UI_LIBRARY_PATH;
/* The final result is only emitted after the installer returns. Flush each
 * entry marker before calls that may block, so a missing final line never
 * becomes evidence that dyld did not enter the loader. */
static void loader_progress(unsigned stage)
{
    fprintf(stderr,"SANTONI GPU: EAGL loader enter stage=%u\n",stage);
    (void)fflush(stderr);
}
static bool library_path_valid(void)
{
    static const char prefix[]="/usr/local/lib/santoni-gpu-ui/",suffix[]="/libsantoni-eagl.dylib";
    size_t base=sizeof(prefix)-1;
    if(sizeof(SANTONI_UI_LIBRARY_PATH)-1!=base+64+sizeof(suffix)-1 ||
        memcmp(library_path,prefix,base) || strcmp(library_path+base+64,suffix))return false;
    for(unsigned i=0;i<64;i++) {
        unsigned char c=(unsigned char)library_path[base+i];
        if(!((c>='0' && c<='9') || (c>='a' && c<='f')))return false;
    }
    return true;
}
bool sgfx_ui_loader_start(void)
{
    pthread_mutex_lock(&loader_lock);
    if(attempted) {bool saved=result;pthread_mutex_unlock(&loader_lock);return saved;}
    attempted=true;unsigned stage=1;loader_progress(stage);
    if(getuid()!=501)goto done;
    stage=2;loader_progress(stage);if(!library_path_valid())goto done;
    /* Register EAGL's Objective-C classes explicitly, without binding the
     * Mesa library's GL entry points to the system OpenGLES implementation. */
    stage=3;loader_progress(stage);
    framework_handle=dlopen("/System/Library/Frameworks/OpenGLES.framework/OpenGLES",RTLD_NOW|RTLD_LOCAL);
    if(!framework_handle)goto done;
    stage=4;loader_progress(stage);library_handle=dlopen(library_path,RTLD_NOW|RTLD_LOCAL|RTLD_FIRST);
    if(!library_handle)goto done;
    stage=5;loader_progress(stage);(void)dlerror();void *symbol=dlsym(library_handle,"sgfx_eagl_install");
    const char *error=dlerror();if(error || !symbol)goto done;
    bool (*install)(void);
    _Static_assert(sizeof(install)==sizeof(symbol),"Darwin function/data pointer geometry");
    memcpy(&install,&symbol,sizeof(install));stage=6;loader_progress(stage);result=install();
done:
    /* Retain every successful dlopen, including failure paths: a runtime
     * race may have observed an implementation pointer before rollback. */
    fprintf(stderr,"SANTONI GPU: EAGL loader installed=%u stage=%u\n",result?1u:0u,stage);
    (void)fflush(stderr);
    pthread_mutex_unlock(&loader_lock);return result;
}
#ifndef SANTONI_UI_LOADER_TEST_NO_CONSTRUCTOR
__attribute__((constructor)) static void loader_initialize(void)
{
    /* No stdio or loader mutex is acquired before this constructor marker.
     * A failed diagnostic must not change the installer's incoming errno. */
    static const char entry[]="SANTONI GPU: EAGL loader constructor entry\n";
    int saved_errno=errno;
    (void)write(STDERR_FILENO,entry,sizeof(entry)-1);
    errno=saved_errno;
    (void)sgfx_ui_loader_start();
}
#endif
