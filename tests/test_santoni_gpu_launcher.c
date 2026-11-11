/* Included after the actual reconstructed adapter/VFS/exec functions. */
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"launcher line %d: %s\n",__LINE__,#x);return 1; } } while(0)

static int PE_parse_boot_argn(const char *s,void *out,int n)
{
    const char *names[]={"santonigpu","santonigpu_user_exec","santonigpu_stock",
        "santonigpu_pixels","santonigpu_submit","santonigpu_session","santonigpu_user",
        "santonigpu_user_test","santonigpu_zap","santonigpu_scm","santonigpu_cache"};
    if(!strcmp(s,"launchdsuffix")) {
        if(!model.suffix)return 0;
        snprintf(out,(size_t)n,"%s",model.suffix);return 1;
    }
    for(unsigned i=0;i<11;i++) if(!strcmp(s,names[i])) {
        assert(n==4);memcpy(out,(unsigned char *)&model.options+4*i,4);return 1;
    }
    abort();
}
static int kernel_mount(const char *fs,vnode_t p,vnode_t v,const char *path,
    void *data,size_t n,int flags,uint32_t kflags,vfs_context_t ctx)
{
    assert(!strcmp(fs,"mockfs") && !p && !v && !strcmp(path,"/dev/sgpu") &&
        n==sizeof(struct sgpu_launch_mount) && !kflags && model.clean==1 && !model.frees);
    model.mounts++;
    struct sgpu_launch_mount args;
    assert(santoni_gpu_user_launch_mount_args(data,&args));
    assert(!santoni_gpu_user_launch_mount_args(&args,&args));
    model.probe_mount=(struct mount){.mnt_flag=(uint32_t)flags,.mnt_kern_flag=MNTK_KERNEL_MOUNT};
    if(model.mount_fail)return EIO;
    return mockfs_santoni_mount(&model.probe_mount,NULL,(uintptr_t)data,ctx);
}
static int setup(const char *probe)
{
    model.options=(struct sgpu_launch_options){3,1,1,1,1,1,1,0,0,0,0};
    model.suffix="release";model.pa=0x91000000;
    void *memory=NULL;CHECK(!posix_memalign(&memory,4096,20480));
    model.memory=memory;CHECK(model.memory!=NULL);
    memset(model.memory,0xa5,20480);model.kva=(uintptr_t)model.memory;
    model.probe=malloc(16635);CHECK(model.probe!=NULL);
    FILE *f=fopen(probe,"rb");CHECK(f!=NULL);
    CHECK(fread(model.probe,1,16635,f)==16635 && fgetc(f)==EOF);fclose(f);
    model.root_mount=(struct mount){.name="hfs"};
    static struct vnode root;root.mp=&model.root_mount;rootvnode=&root;
    return 0;
}
static int normal(void)
{
    CHECK(!santoni_gpu_user_launch_worker_ready(3));
    const char *path=santoni_gpu_user_launch_path();CHECK(path && !strcmp(path,"/dev/sgpu/sbin/launchd"));
    CHECK(model.allocations==1 && model.clean==1 && model.nodes==1 && model.mounts==1 && !model.frees);
    CHECK(launch.report.retained && launch.report.ready && launch.mounted);
    CHECK(!santoni_gpu_user_launch_worker_ready(3));
    CHECK(!santoni_gpu_user_launch_mount_args(&launch.mount,&launch.mount));
    mockfs_mount_t m=model.probe_mount.mnt_data;CHECK(m && m->mockfs_root);
    mockfs_fsnode_t root=m->mockfs_root,file=NULL,dev=NULL;
    CHECK(!mockfs_fsnode_child_by_type(root,MOCKFS_FILE,&file) && file && file->size==16635);
    CHECK(!mockfs_fsnode_child_by_type(root,MOCKFS_DEV,&dev) && dev && !dev->size);
    vnode_t rv=NULL,fv=NULL;CHECK(!mockfs_fsnode_vnode(root,&rv));
    char name[]="sbin/";struct componentname c={LOOKUP,4,name};
    struct vnop_lookup_args a={rv,&fv,&c,&model_context};
    CHECK(!mockfs_lookup(&a) && fv==rv && name[4]=='/');vnode_put(fv);
    char executable[]="launchd/";c.cn_nameptr=executable;c.cn_namelen=7;
    CHECK(!mockfs_lookup(&a) && fv && fv->v_type==VREG && executable[7]=='/');
    CHECK(model.pager==1);
    struct vnode_attr attrs;struct vnop_getattr_args ga={fv,&attrs};
    CHECK(!mockfs_getattr(&ga) && attrs.va_mode==0500 && !attrs.va_uid && !attrs.va_gid && attrs.va_data_size==16635);
    santoni_gpu_user_launch_exec_result(0);CHECK(santoni_gpu_user_launch_worker_ready(3));
    santoni_gpu_user_launch_exec_result(EIO);CHECK(santoni_gpu_user_launch_worker_ready(3) && !launch.error);
    CHECK(mockfs_unmount(&model.probe_mount,MNT_FORCE,&model_context)==EBUSY && !model.vflushes && !model.frees);
    CHECK(!santoni_gpu_user_launch_path() && model.allocations==1);
    return 0;
}
static int option_case(const char *s)
{
    if(!strcmp(s,"off"))model.options.enabled=0;
    else if(!strcmp(s,"mode1"))model.options.mode=1;
    else if(!strcmp(s,"mode2"))model.options.mode=2;
    else if(!strcmp(s,"user-test"))model.options.user_test=1;
    else if(!strcmp(s,"zap"))model.options.zap=1;
    else if(!strcmp(s,"scm"))model.options.scm=1;
    else if(!strcmp(s,"cache"))model.options.cache=1;
    else if(!strcmp(s,"no-suffix"))model.suffix=NULL;
    else if(!strcmp(s,"other-suffix"))model.suffix="debug";
    else if(!strcmp(s,"not-pid1"))model_proc.pid=7;
    else if(!strcmp(s,"page16k")){page_shift=14;page_size=16384;}
    else return 2;
    CHECK(!santoni_gpu_user_launch_path() && !model.allocations && !model.dt && !model.root_lookups && !model.nodes);
    CHECK(santoni_gpu_user_launch_worker_ready(model.options.mode)==(!strcmp(s,"off")));
    return 0;
}
static int prepare_failure(const char *s)
{
    if(!strcmp(s,"not-hfs"))model.root_mount.name="mockfs";
    else if(!strcmp(s,"missing-dt"))model.dt_fail=1;
    else if(!strcmp(s,"allocation"))model.alloc_fail=1;
    else if(!strcmp(s,"noncontig"))model.noncontig=1;
    else if(!strcmp(s,"missing-last"))model.missing_last=1;
    else if(!strcmp(s,"major"))model.major_fail=1;
    else if(!strcmp(s,"node"))model.node_fail=1;
    else if(!strcmp(s,"mount"))model.mount_fail=1;
    else if(!strcmp(s,"mount-allocation"))model.tree_fail=1;
    else return 2;
    CHECK(!santoni_gpu_user_launch_path() && !santoni_gpu_user_launch_worker_ready(3));
    CHECK(!santoni_gpu_user_launch_path());
    bool mapped=!strcmp(s,"noncontig") || !strcmp(s,"missing-last");
    CHECK(model.frees==(unsigned)mapped);
    if(model.clean)CHECK(launch.report.exposed && launch.report.retained && !model.frees);
    CHECK(launch.stage==LAUNCH_FAILED && launch.error);
    int first=launch.error;santoni_gpu_user_launch_exec_result(0);
    CHECK(launch.error==first && !santoni_gpu_user_launch_worker_ready(3));
    return 0;
}
static int pager_failure(const char *s)
{
    if(strcmp(s,"ubc") && strcmp(s,"pager") && strcmp(s,"bad-span") &&
        strcmp(s,"bad-eof") && strcmp(s,"vnode")) return 2;
    CHECK(santoni_gpu_user_launch_path()!=NULL);
    mockfs_mount_t m=model.probe_mount.mnt_data;mockfs_fsnode_t file=NULL;
    CHECK(!mockfs_fsnode_child_by_type(m->mockfs_root,MOCKFS_FILE,&file));
    if(!strcmp(s,"ubc"))model.ubc_fail=1;
    else if(!strcmp(s,"pager"))model.pager_fail=1;
    else if(!strcmp(s,"bad-span"))m->santoni_probe_span_bytes=16635;
    else if(!strcmp(s,"bad-eof"))m->santoni_probe_file_bytes=20480;
    else if(!strcmp(s,"vnode"))model.create_fail=1;
    else return 2;
    vnode_t out=(void *)(uintptr_t)1;
    CHECK(mockfs_fsnode_vnode(file,&out)!=0 && out==(void *)(uintptr_t)1 && !model.frees && !model.locked);
    if(model.create_fail) {
        CHECK(!m->santoni_probe_failed && !model.puts && !model.pager);
    } else {
        CHECK(m->santoni_probe_failed && model.puts==1);
        unsigned before=model.creates;
        CHECK(mockfs_fsnode_vnode(file,&out)==EIO && model.creates==before && model.puts==1);
    }
    santoni_gpu_user_launch_exec_result(EIO);CHECK(!santoni_gpu_user_launch_worker_ready(3));
    santoni_gpu_user_launch_exec_result(0);CHECK(launch.error==EIO && launch.stage==LAUNCH_FAILED);
    return 0;
}
static int mount_guard(const char *s)
{
    launch.attempted=true;launch.stage=LAUNCH_PREPARING;launch.mount_inflight=true;
    launch.mount=(struct sgpu_launch_mount){model.kva,16635,20480};
    struct mount mp={.mnt_flag=MNT_RDONLY|MNT_NOSUID|MNT_NOATIME,.mnt_kern_flag=MNTK_KERNEL_MOUNT};
    vnode_t dev=NULL;void *data=&launch.mount;
    if(!strcmp(s,"mount-user"))model_context.kernel=false;
    else if(!strcmp(s,"mount-no-kflag"))mp.mnt_kern_flag=0;
    else if(!strcmp(s,"mount-writable"))mp.mnt_flag&=~MNT_RDONLY;
    else if(!strcmp(s,"mount-suid"))mp.mnt_flag&=~MNT_NOSUID;
    else if(!strcmp(s,"mount-noexec"))mp.mnt_flag|=MNT_NOEXEC;
    else if(!strcmp(s,"mount-update"))mp.mnt_flag|=MNT_UPDATE;
    else if(!strcmp(s,"mount-root"))mp.mnt_flag|=MNT_ROOTFS;
    else if(!strcmp(s,"mount-device"))dev=rootvnode;
    else if(!strcmp(s,"mount-forged"))data=&mp;
    else if(!strcmp(s,"mount-outside"))launch.mount_inflight=false;
    else return 2;
    CHECK(mockfs_santoni_mount(&mp,dev,(uintptr_t)data,&model_context)==EINVAL && !mp.mnt_data && !model.tree_alloc);
    return 0;
}
static int init_case(const char *s)
{
    bool off=!strcmp(s,"init-off"),failed=!strcmp(s,"init-fallback"),single=!strcmp(s,"init-single");
    if(off)model.options.enabled=0;
    if(failed)model.exec_fail=ENOENT;
    if(single)boothowto=RB_SINGLE;
    load_init_program(&model_proc);
    CHECK(model.execs==(failed?2u:1u));
    CHECK(!strcmp(model.exec_paths[0],off?"/sbin/launchd":"/dev/sgpu/sbin/launchd"));
    if(failed)CHECK(!strcmp(model.exec_paths[1],"/sbin/launchd") && launch.stage==LAUNCH_FAILED && !santoni_gpu_user_launch_worker_ready(3));
    if(single)CHECK(!strcmp(model.exec_arg[0],"-s"));
    if(off)CHECK(!model.allocations && !model.dt);
    else CHECK(!model.frees && launch.report.retained);
    return 0;
}
int main(int argc,char **argv)
{
    if(argc!=3)return 2;
    int rc=setup(argv[1]);if(rc)return rc;
    const char *s=argv[2];
    if(!strcmp(s,"normal"))rc=normal();
    else if(!strncmp(s,"init-",5))rc=init_case(s);
    else {rc=option_case(s);if(rc==2)rc=prepare_failure(s);if(rc==2)rc=pager_failure(s);if(rc==2)rc=mount_guard(s);}
    if(rc==2)fprintf(stderr,"unknown scenario %s\n",s);
    if(!rc)printf("PASS new launcher adapter %s\n",s);
    return rc;
}
