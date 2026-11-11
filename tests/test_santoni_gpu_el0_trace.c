/* Included after the actual new receiver/helper functions. No GPU model. */
static void setup_trace(void)
{
    memset(&tm,0,sizeof(tm)); memset(&launch,0,sizeof(launch));
    mockfs_santoni_trace_events=0;
    memset(&mockfs_santoni_trace_diag,0,sizeof(mockfs_santoni_trace_diag));
    tm.options=(struct sgpu_launch_options){.mode=3,.enabled=1,.stock=1,.pixels=1,
        .submit=1,.session=1,.user=1}; tm.suffix="release";
    tm.proc.pid=2; tm.other_proc.pid=3; tm.current=&tm.proc;
    tm.ctx=(struct trace_context){.root=true,.proc=&tm.proc};
    tm.mount.santoni_probe_kva=UINT64_C(0x60000000);
    tm.mount.santoni_probe_file_bytes=16635; tm.mount.santoni_probe_span_bytes=20480;
    tm.vfs.mnt_data=&tm.mount;
    tm.node=(struct trace_node){.type=MOCKFS_FILE,.mnt=&tm.vfs};
    tm.vnode=(struct trace_vnode){.type=VREG,.data=&tm.node,.mount=&tm.vfs};
    tm.executable=&tm.vnode;
    launch.stage=LAUNCH_READY; launch.mounted=true;
    launch.mount=(struct sgpu_launch_mount){.kva=tm.mount.santoni_probe_kva,
        .file_bytes=16635,.span_bytes=20480};
}
static void invoke_trace(struct vnop_ioctl_args *a, int expected)
{
    struct sgpu_launch_trace_record before;
    if (a && a->a_data) memcpy(&before,a->a_data,sizeof(before));
    unsigned printed=tm.prints,used=mockfs_santoni_trace_events;
    struct sgpu_launch_mount backing=launch.mount;
    assert(mockfs_santoni_ioctl(a)==expected);
    if (a && a->a_data) assert(!memcmp(&before,a->a_data,sizeof(before)));
    assert(!memcmp(&backing,&launch.mount,sizeof(backing)));
    assert(!tm.locked && !tm.mount.mockfs_mnt_mtx && tm.locks==tm.unlocks);
    assert(!tm.vnode.refs && !tm.other_vnode.refs);
    if (expected) assert(tm.prints==printed && mockfs_santoni_trace_events==used);
    else assert(tm.prints==printed+1 && mockfs_santoni_trace_events==used+1);
}
static void *diag_traffic(void *opaque)
{
    (void)opaque;
    for (unsigned i=0;i<2000;i++) {
        mockfs_santoni_diag_note(true,0,0);
        mockfs_santoni_diag_note(true,1,0);
        mockfs_santoni_diag_note(false,0,0);
        assert(mockfs_santoni_diag_refuse(false,3,EACCES)==EACCES);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    assert(argc==2); const char *name=argv[1]; setup_trace();
    struct sgpu_launch_trace_record r={.version=1,.bytes=64,.event=SG_LTRACE_ENTRY,.value=2};
    struct vnop_ioctl_args a={.a_vp=&tm.vnode,.a_command=SGPU_LAUNCH_TRACE_IOCTL,
        .a_data=(void *)&r,.a_fflag=FREAD,.a_context=&tm.ctx};
    int expected=ENOTSUP;
    if (!strcmp(name,"normal")) {
        struct vnop_open_args open={&tm.vnode,FREAD|0x01000000,&tm.ctx};
        struct vnop_close_args close={&tm.vnode,FREAD,&tm.ctx};
        assert(mockfs_santoni_open(&open)==0);
        invoke_trace(&a,0); assert(strstr(tm.line,"event=1 pid=2 status=0 value=2 record=1"));
        assert(mockfs_santoni_close(&close)==0);
        assert(tm.gets==2 && tm.puts==2);
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.open_attempts==1 && d.open_accepted==1 && !d.open_refused &&
            d.ioctl_attempts==1 && d.ioctl_accepted==1 && !d.ioctl_refused &&
            !d.open_refuse_stage && !d.ioctl_refuse_stage && d.seen_open==1 && d.seen_ioctl==1);
    } else if (!strcmp(name,"result")) {
        r=(struct sgpu_launch_trace_record){.version=1,.bytes=64,.event=SG_LTRACE_RESULT,
            .pass=1,.sent=32,.verified=32,.negative=7};
        invoke_trace(&a,0);
        assert(strstr(tm.line,"RESULT pass=1 pid=2 sent=32 verified=32 negative=7 error=0 errno=0"));
    } else if (!strcmp(name,"failure-result")) {
        r=(struct sgpu_launch_trace_record){.version=1,.bytes=64,.event=SG_LTRACE_RESULT,
            .sent=2,.verified=1,.negative=6,.error=1,.transport_errno=45};
        invoke_trace(&a,0); assert(strstr(tm.line,"error=1 errno=45"));
    } else if (!strcmp(name,"quota")) {
        for (unsigned i=0;i<16;i++) invoke_trace(&a,0);
        invoke_trace(&a,EBUSY); invoke_trace(&a,EBUSY);
        assert(tm.prints==16 && mockfs_santoni_trace_events==16);
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.ioctl_attempts==18 && d.ioctl_accepted==16 && d.ioctl_refused==2 &&
            d.ioctl_refuse_stage==5 && d.seen_ioctl==1);
    } else if (!strcmp(name,"diag-open-flags")) {
        struct vnop_open_args open={&tm.vnode,FREAD|FWRITE,&tm.ctx};
        assert(mockfs_santoni_open(&open)==EACCES);
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.open_attempts==1 && d.open_accepted==0 && d.open_refused==1 &&
            d.open_refuse_stage==2 && d.seen_open==1);
    } else if (!strcmp(name,"diag-open-access")) {
        tm.ctx.proc=&tm.other_proc;
        struct vnop_open_args open={&tm.vnode,FREAD,&tm.ctx};
        assert(mockfs_santoni_open(&open)==EACCES);
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.open_refuse_stage==3 && d.open_refused==1 && d.open_accepted==0);
    } else if (!strcmp(name,"diag-ioctl-abi")) {
        r.version=2; invoke_trace(&a,EINVAL);
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.ioctl_refuse_stage==4 && d.ioctl_refused==1 && d.ioctl_accepted==0);
    } else if (!strcmp(name,"diag-ioctl-wrong-mount")) {
        tm.mount.santoni_probe_kva+=4096; invoke_trace(&a,ENOTSUP);
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.ioctl_refuse_stage==1 && d.ioctl_refused==1 && d.seen_ioctl==1 &&
            d.ioctl_attempts==0);
    } else if (!strcmp(name,"diag-silent")) {
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(!d.open_attempts && !d.ioctl_attempts && !d.seen_open && !d.seen_ioctl &&
            !d.open_refuse_stage && !d.ioctl_refuse_stage && !d.open_refused && !d.ioctl_refused);
    } else if (!strcmp(name,"diag-saturation")) {
        mockfs_santoni_trace_diag=(struct sgpu_launch_trace_diag){
            .open_attempts=UINT32_MAX-1,.open_accepted=UINT32_MAX,
            .ioctl_attempts=UINT32_MAX,.ioctl_refused=UINT32_MAX-1};
        for (unsigned i=0;i<3;i++) {
            mockfs_santoni_diag_note(true,0,0); mockfs_santoni_diag_note(true,1,0);
            mockfs_santoni_diag_note(false,0,0);
            assert(mockfs_santoni_diag_refuse(false,4,EINVAL)==EINVAL);
        }
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.open_attempts==UINT32_MAX && d.open_accepted==UINT32_MAX &&
            d.ioctl_attempts==UINT32_MAX && d.ioctl_refused==UINT32_MAX &&
            d.ioctl_refuse_stage==4 && !diag_locked);
    } else if (!strcmp(name,"diag-first-wins")) {
        assert(mockfs_santoni_diag_refuse(true,2,EACCES)==EACCES);
        assert(mockfs_santoni_diag_refuse(true,3,EACCES)==EACCES);
        assert(mockfs_santoni_diag_refuse(false,1,ENOTSUP)==ENOTSUP);
        assert(mockfs_santoni_diag_refuse(false,5,EBUSY)==EBUSY);
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.open_refuse_stage==2 && d.ioctl_refuse_stage==1 &&
            d.open_refused==2 && d.ioctl_refused==2 && !diag_locked);
    } else if (!strcmp(name,"diag-late")) {
        struct sgpu_launch_trace_diag before,after;
        santoni_gpu_user_launch_trace_snapshot(NULL); assert(!diag_locked);
        santoni_gpu_user_launch_trace_snapshot(&before);
        invoke_trace(&a,0);
        santoni_gpu_user_launch_trace_snapshot(&after);
        assert(!before.seen_ioctl && !before.ioctl_attempts &&
            after.seen_ioctl==1 && after.ioctl_attempts==1 && after.ioctl_accepted==1);
        assert(!diag_locked);
    } else if (!strcmp(name,"diag-concurrent")) {
        assert(mockfs_santoni_diag_refuse(false,1,ENOTSUP)==ENOTSUP);
        pthread_t workers[8];
        for (unsigned i=0;i<8;i++) assert(!pthread_create(&workers[i],NULL,diag_traffic,NULL));
        uint32_t last=0;
        for (unsigned i=0;i<2000;i++) {
            struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
            assert(d.ioctl_refuse_stage==1 && d.ioctl_refused>=last &&
                d.open_accepted<=d.open_attempts && !diag_locked);
            last=d.ioctl_refused;
        }
        for (unsigned i=0;i<8;i++) assert(!pthread_join(workers[i],NULL));
        struct sgpu_launch_trace_diag d; santoni_gpu_user_launch_trace_snapshot(&d);
        assert(d.open_attempts==16000 && d.open_accepted==16000 &&
            d.ioctl_attempts==16000 && d.ioctl_refused==16001 && d.ioctl_refuse_stage==1);
        assert(d.seen_open==1 && d.seen_ioctl==1 && !diag_locked);
    } else if (!strcmp(name,"reserved")) {
        unsigned char *bytes=(void *)&r;
        for (unsigned i=44;i<64;i++) { bytes[i]=1; invoke_trace(&a,EINVAL); bytes[i]=0; }
        invoke_trace(&a,0);
    } else if (!strcmp(name,"non-result-fields")) {
        uint32_t *words=(void *)&r;
        for (unsigned i=5;i<11;i++) { words[i]=1; invoke_trace(&a,EINVAL); words[i]=0; }
        invoke_trace(&a,0);
    } else if (!strcmp(name,"forged-pass")) {
        r.event=SG_LTRACE_RESULT; r.value=0; r.pass=1;
        r.sent=32; r.verified=32; r.negative=7;
        r.sent=31; r.verified=31; invoke_trace(&a,EINVAL);
        r.sent=32; r.verified=31; invoke_trace(&a,EINVAL);
        r.verified=32; r.negative=6; invoke_trace(&a,EINVAL);
        r.negative=7; r.error=1; invoke_trace(&a,EINVAL);
        r.error=0; r.transport_errno=45; invoke_trace(&a,EINVAL);
        r.transport_errno=0; r.status=1; invoke_trace(&a,EINVAL);
        r.status=0; r.value=1; invoke_trace(&a,EINVAL);
    } else if (!strcmp(name,"open-write")) {
        struct vnop_open_args open={&tm.vnode,FREAD|FWRITE,&tm.ctx};
        assert(mockfs_santoni_open(&open)==EACCES);
        open.a_mode=0; assert(mockfs_santoni_open(&open)==EACCES); assert(!tm.gets);
    } else if (!strcmp(name,"close-cloexec")) {
        struct vnop_close_args close={&tm.vnode,FREAD,NULL};
        tm.executable=&tm.other_vnode; tm.ctx.root=false;
        assert(mockfs_santoni_close(&close)==0 && !tm.gets && !tm.prints);
        close.a_fflag=FWRITE; assert(mockfs_santoni_close(&close)==ENOTSUP);
        close.a_vp=&tm.other_vnode; close.a_fflag=FREAD;
        assert(mockfs_santoni_close(&close)==ENOTSUP);
    } else if (!strcmp(name,"null-args")) {
        invoke_trace(NULL,ENOTSUP);
        assert(mockfs_santoni_open(NULL)==ENOTSUP && mockfs_santoni_close(NULL)==ENOTSUP);
    } else {
        if (!strcmp(name,"off")) tm.options.enabled=0;
        else if (!strcmp(name,"mode1")) tm.options.mode=1;
        else if (!strcmp(name,"mode2")) tm.options.mode=2;
        else if (!strcmp(name,"wrong-flags")) tm.options.user_test=1;
        else if (!strcmp(name,"no-suffix")) tm.suffix=NULL;
        else if (!strcmp(name,"wrong-suffix")) tm.suffix="development";
        else if (!strcmp(name,"preparing")) launch.stage=LAUNCH_PREPARING;
        else if (!strcmp(name,"failed")) launch.stage=LAUNCH_FAILED;
        else if (!strcmp(name,"unmounted")) launch.mounted=false;
        else if (!strcmp(name,"wrong-backing")) tm.mount.santoni_probe_kva+=4096;
        else if (!strcmp(name,"wrong-eof")) tm.mount.santoni_probe_file_bytes++;
        else if (!strcmp(name,"wrong-span")) tm.mount.santoni_probe_span_bytes-=4096;
        else if (!strcmp(name,"null-vnode")) a.a_vp=NULL;
        else if (!strcmp(name,"directory")) tm.vnode.type=VDIR;
        else if (!strcmp(name,"null-node")) tm.vnode.data=NULL;
        else if (!strcmp(name,"wrong-node")) tm.node.type=0;
        else if (!strcmp(name,"wrong-mount")) tm.vnode.mount=&tm.other_vfs;
        else if (!strcmp(name,"null-mount")) tm.node.mnt=NULL;
        else if (!strcmp(name,"null-mount-data")) tm.vfs.mnt_data=NULL;
        else if (!strcmp(name,"pager-failed")) tm.mount.santoni_probe_failed=true;
        else if (!strcmp(name,"wrong-command")) a.a_command++;
        else if (!strcmp(name,"wide-command")) a.a_command+=UINT64_C(1)<<32;
        else if (!strcmp(name,"kernel-context")) { tm.ctx.kernel=true; expected=EACCES; }
        else if (!strcmp(name,"null-context")) { a.a_context=NULL; expected=EACCES; }
        else if (!strcmp(name,"null-process")) { tm.ctx.proc=NULL; expected=EACCES; }
        else if (!strcmp(name,"foreign-process")) { tm.ctx.proc=&tm.other_proc; expected=EACCES; }
        else if (!strcmp(name,"pid0")) { tm.proc.pid=0; expected=EACCES; }
        else if (!strcmp(name,"nonroot")) { tm.ctx.root=false; expected=EACCES; }
        else if (!strcmp(name,"missing-executable")) { tm.executable=NULL; expected=EACCES; }
        else if (!strcmp(name,"other-executable")) { tm.executable=&tm.other_vnode; expected=EACCES; }
        else if (!strcmp(name,"null-record")) { a.a_data=NULL; expected=EINVAL; }
        else if (!strcmp(name,"write-descriptor")) { a.a_fflag=FREAD|FWRITE; expected=EINVAL; }
        else if (!strcmp(name,"version")) { r.version=2; expected=EINVAL; }
        else if (!strcmp(name,"size")) { r.bytes=128; expected=EINVAL; }
        else if (!strcmp(name,"event")) { r.event=10; expected=EINVAL; }
        else if (!strcmp(name,"status")) { r.status=2; expected=EINVAL; }
        else if (!strcmp(name,"bounds")) { r.sent=33; expected=EINVAL; }
        else if (!strcmp(name,"verification")) { r.sent=1; r.verified=2; expected=EINVAL; }
        else if (!strcmp(name,"negative")) { r.negative=8; expected=EINVAL; }
        else if (!strcmp(name,"error")) { r.error=7; expected=EINVAL; }
        else abort();
        invoke_trace(&a,expected);
    }
    assert(!diag_locked && !tm.locked && tm.locks==tm.unlocks);
    assert(!tm.vnode.refs && !tm.other_vnode.refs);
    puts(name); return 0;
}
