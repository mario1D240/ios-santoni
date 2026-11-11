/* Actual explicit loader. dyld, UID and the audited installer are modeled. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#undef pthread_mutex_lock
int pthread_mutex_lock(pthread_mutex_t *);

bool sgfx_ui_loader_start(void);
static unsigned scenario,opens,symbols,errors,installs,closes;
int sgfx_test_loader_mutex_lock(pthread_mutex_t *mutex)
{
    const char *value=getenv("SGFX_LOADER_CASE");
    if(value)scenario=(unsigned)strtoul(value,NULL,10);
    if(scenario==15)_exit(42);
    return pthread_mutex_lock(mutex);
}
static char events[32];static unsigned event_count;
static void event(char c){assert(event_count<31);events[event_count++]=c;}
uid_t getuid(void)
{
    /* Constructor runs before main; only this fixture reads a test setting. */
    const char *value=getenv("SGFX_LOADER_CASE");if(value)scenario=(unsigned)strtoul(value,NULL,10);
    event('U');return scenario==1?0:scenario==2?502:501;
}
static bool install(void){installs++;event('I');if(scenario==13)_exit(42);return scenario!=7;}
void *dlopen(const char *path,int flags)
{
    opens++;
    if(opens==1){
        assert(!strcmp(path,"/System/Library/Frameworks/OpenGLES.framework/OpenGLES") && flags==(RTLD_NOW|RTLD_LOCAL));event('F');
        if(scenario==14)_exit(42);
        return scenario==3?NULL:(void *)0x100;
    }
    assert(opens==2 && flags==(RTLD_NOW|RTLD_LOCAL|RTLD_FIRST));event('L');
    assert(!strcmp(path,"/usr/local/lib/santoni-gpu-ui/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/libsantoni-eagl.dylib"));
    return scenario==4?NULL:(void *)0x200;
}
void *dlsym(void *handle,const char *name)
{
    assert(handle==(void *)0x200 && !strcmp(name,"sgfx_eagl_install"));symbols++;event('S');
    if(scenario==5)return NULL;
    bool (*function)(void)=install;void *out;
    _Static_assert(sizeof(function)==sizeof(out),"fixture pointer geometry");memcpy(&out,&function,sizeof(out));return out;
}
char *dlerror(void){errors++;event('E');return scenario==6 && errors==2?"modeled lookup failure":NULL;}
int dlclose(void *handle){(void)handle;closes++;assert(!"loader must retain successful image handles");return 0;}
static void *start_thread(void *opaque){*(bool *)opaque=sgfx_ui_loader_start();return NULL;}
int main(int argc,char **argv)
{
    assert(argc==2);scenario=(unsigned)strtoul(argv[1],NULL,10);assert(scenario<16);
    bool result;
    if(scenario==9) {
        bool values[8]={false};pthread_t threads[8];
        for(unsigned i=0;i<8;i++)assert(!pthread_create(&threads[i],NULL,start_thread,&values[i]));
        for(unsigned i=0;i<8;i++){assert(!pthread_join(threads[i],NULL));assert(values[i]);}result=true;
    }else result=sgfx_ui_loader_start();
    assert(result==(scenario==0 || scenario==8 || scenario==9));
    assert(!closes);
    if(scenario==1 || scenario==2 || scenario>=10)assert(!opens && !symbols && !installs && !strcmp(events,"U"));
    else if(scenario==3)assert(opens==1 && !symbols && !installs && !strcmp(events,"UF"));
    else if(scenario==4)assert(opens==2 && !symbols && !installs && !strcmp(events,"UFL"));
    else if(scenario==5 || scenario==6)assert(opens==2 && symbols==1 && !installs && !strcmp(events,"UFLESE"));
    else assert(opens==2 && symbols==1 && installs==1 && !strcmp(events,"UFLESEI"));
    unsigned before=event_count;
    assert(sgfx_ui_loader_start()==result && event_count==before);
    return 0;
}
