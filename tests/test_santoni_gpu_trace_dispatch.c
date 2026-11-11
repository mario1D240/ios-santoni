/* Exercises exact extracted syscall/file/vnode/receiver functions. */
static void setup_trace(void)
{
    memset(&tm,0,sizeof(tm)); memset(&launch,0,sizeof(launch));
    mockfs_santoni_trace_events=0;
    memset(&mockfs_santoni_trace_diag,0,sizeof(mockfs_santoni_trace_diag));
    tm.options=(struct sgpu_launch_options){.mode=3,.enabled=1,.stock=1,.pixels=1,
        .submit=1,.session=1,.user=1}; tm.suffix="release";
    tm.proc.pid=2; tm.other_proc.pid=3; tm.current=&tm.proc;
    tm.ctx=(struct vfs_context){.root=true,.proc=&tm.proc};
    tm.mount.santoni_probe_kva=UINT64_C(0x60000000);
    tm.mount.santoni_probe_file_bytes=16635; tm.mount.santoni_probe_span_bytes=20480;
    tm.vfs.mnt_data=&tm.mount;
    tm.node=(struct trace_node){.type=MOCKFS_FILE,.mnt=&tm.vfs};
    tm.vnode=(struct vnode){.type=VREG,.data=&tm.node,.mount=&tm.vfs};
    tm.executable=&tm.vnode;
    launch.stage=LAUNCH_READY; launch.mounted=true;
    launch.mount=(struct sgpu_launch_mount){.kva=tm.mount.santoni_probe_kva,
        .file_bytes=16635,.span_bytes=20480};
    memset(&dm,0,sizeof(dm)); dispatch_iocount=0;
    tm.vnode.op=mockfs_vnodeop_p;
    dm.ops.fo_ioctl=vn_ioctl;
    dm.fg=(struct fileglob){.fg_flag=FREAD,.fg_cred=true,.data=&tm.vnode,.fg_ops=&dm.ops};
    dm.fp.fp_glob=&dm.fg;
}
static void invoke_dispatch(struct sgpu_launch_trace_record *r,u_long command,int expected,
                            unsigned receiver_calls,unsigned devices)
{
    struct sgpu_launch_trace_record before=*r;
    unsigned received=dm.receiver_calls,devs=dm.device_calls,printed=tm.prints;
    struct sgpu_launch_mount backing=launch.mount;
    dm.user=(void *)r; dm.command=command;
    struct ioctl_args args={5,command,(uintptr_t)r}; int32_t retval=0;
    assert(sgpu_host_ioctl(tm.current,&args,&retval)==expected);
    assert(dm.receiver_calls==received+receiver_calls && dm.device_calls==devs+devices);
    assert(tm.prints==printed+(receiver_calls && !expected));
    assert(!memcmp(&before,r,sizeof(before)) && !memcmp(&backing,&launch.mount,sizeof(backing)));
    assert(dm.copyouts==0 && !dm.fdlocked && !dm.fprefs && dm.fdlocks==dm.fdunlocks);
    assert(!dispatch_iocount && tm.gets==tm.puts && !tm.vnode.refs && !tm.other_vnode.refs);
    assert(!tm.locked && !diag_locked && tm.locks==tm.unlocks);
}
int main(int argc,char **argv)
{
    assert(argc==2); const char *name=argv[1]; setup_trace();
    struct sgpu_launch_trace_record r={.version=1,.bytes=64,.event=SG_LTRACE_ENTRY,.value=2};
    u_long command=SGPU_LAUNCH_TRACE_IOCTL;
    int expected=0; unsigned receiver_calls=1,devices=0;
    if (!strcmp(name,"baseline")) { expected=ENOTTY; receiver_calls=0; }
    else if (!strcmp(name,"entry")) {}
    else if (!strcmp(name,"result"))
        r=(struct sgpu_launch_trace_record){.version=1,.bytes=64,.event=SG_LTRACE_RESULT,
            .pass=1,.sent=32,.verified=32,.negative=7};
    else if (!strcmp(name,"failure-result"))
        r=(struct sgpu_launch_trace_record){.version=1,.bytes=64,.event=SG_LTRACE_RESULT,
            .sent=2,.verified=1,.negative=6,.error=1,.transport_errno=45};
    else if (!strcmp(name,"other-vector")) { tm.vnode.op=other_ops; expected=ENOTTY; receiver_calls=0; }
    else if (!strcmp(name,"directory")) { tm.vnode.type=VDIR; expected=ENOTTY; receiver_calls=0; }
    else if (!strcmp(name,"other-command")) { command++; expected=ENOTTY; receiver_calls=0; }
    else if (!strcmp(name,"wide-command")) { command+=UINT64_C(1)<<32; expected=ENOTTY; receiver_calls=0; }
    else if (!strcmp(name,"copyin-error")) { dm.copyin_error=EFAULT; expected=EFAULT; receiver_calls=0; }
    else if (!strcmp(name,"file-mac")) { dm.file_mac_error=EPERM; expected=EPERM; receiver_calls=0; }
    else if (!strcmp(name,"vnode-mac")) { dm.vnode_mac_error=EPERM; expected=EPERM; receiver_calls=0; }
    else if (!strcmp(name,"vnode-get")) { dm.get_error=ENOENT; expected=ENOENT; receiver_calls=0; }
    else if (!strcmp(name,"bad-fd")) { dm.lookup_error=EBADF; expected=EBADF; receiver_calls=0; }
    else if (!strcmp(name,"no-access")) { dm.fg.fg_flag=0; expected=EBADF; receiver_calls=0; }
    else if (!strcmp(name,"off")) { tm.options.enabled=0; expected=ENOTSUP; }
    else if (!strcmp(name,"mode1")) { tm.options.mode=1; expected=ENOTSUP; }
    else if (!strcmp(name,"mode2")) { tm.options.mode=2; expected=ENOTSUP; }
    else if (!strcmp(name,"nonroot")) { dm.fg.fg_cred=false; expected=EACCES; }
    else if (!strcmp(name,"kernel-context")) { tm.ctx.kernel=true; expected=EACCES; }
    else if (!strcmp(name,"other-executable")) { tm.executable=&tm.other_vnode; expected=EACCES; }
    else if (!strcmp(name,"backing")) { tm.mount.santoni_probe_kva+=4096; expected=ENOTSUP; }
    else if (!strcmp(name,"record")) { r.version=2; expected=EINVAL; }
    else if (!strcmp(name,"reserved")) { r.reserved[4]=1; expected=EINVAL; }
    else if (!strcmp(name,"write-descriptor")) { dm.fg.fg_flag=FREAD|FWRITE; expected=EINVAL; }
    else if (!strcmp(name,"quota")) {
        for (unsigned i=0;i<16;i++) invoke_dispatch(&r,command,0,1,0);
        invoke_dispatch(&r,command,EBUSY,1,0); invoke_dispatch(&r,command,EBUSY,1,0);
        assert(mockfs_santoni_trace_events==16 && dm.receiver_calls==18 && tm.prints==16);
        puts(name); return 0;
    } else if (!strcmp(name,"character") || !strcmp(name,"block") || !strcmp(name,"fifo")) {
        tm.vnode.type=!strcmp(name,"character")?VCHR:!strcmp(name,"block")?VBLK:VFIFO;
        expected=73; receiver_calls=0; devices=1;
    } else if (!strcmp(name,"fionread")) {
        dm.command=FIONREAD; dm.fg.fg_offset=16630; dm.fprefs=1;
        int bytes=-1; assert(vn_ioctl(&dm.fp,FIONREAD,(void *)&bytes,&tm.ctx)==0);
        assert(bytes==5 && !dm.vnop_calls && !tm.vnode.refs && tm.gets==tm.puts);
        puts(name); return 0;
    } else abort();
    invoke_dispatch(&r,command,expected,receiver_calls,devices);
    assert(dm.copyins==1);
    if (!strcmp(name,"copyin-error")) assert(!dm.lookups && !dm.file_mac && !dm.vnode_mac);
    else if (!strcmp(name,"bad-fd")) assert(dm.lookups==1 && !dm.drops && !dm.file_mac);
    else if (!strcmp(name,"no-access")) assert(dm.drops==1 && !dm.file_mac && !dm.vnode_gets);
    else if (!strcmp(name,"file-mac")) assert(dm.file_mac==1 && !dm.vnode_gets);
    else if (!strcmp(name,"vnode-get")) assert(dm.vnode_gets==1 && !dm.vnode_mac);
    else assert(dm.file_mac==1 && dm.vnode_mac==1);
    if (!strcmp(name,"entry")) assert(strstr(tm.line,"TRACE event=1 pid=2 status=0 value=2 record=1"));
    if (!strcmp(name,"result")) assert(strstr(tm.line,"RESULT pass=1 pid=2 sent=32 verified=32 negative=7 error=0 errno=0"));
    if (!strcmp(name,"failure-result")) assert(strstr(tm.line,"RESULT pass=0 pid=2 sent=2 verified=1 negative=6 error=1 errno=45"));
    if (devices) assert(dm.flags==dm.fg.fg_flag && !mockfs_santoni_trace_events);
    puts(name); return 0;
}
