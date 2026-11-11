"""Exact boot call/order graph for built-in renderer dyld policy registration.

Does not execute the kernel or prove scheduler/VFS/platform calls return.
Requires complete supplied instruction graphs; only successful reachability to
the normal BSD user-task bootstrap is compared, including failure branches.
"""
BOOT='_kernel_bootstrap_thread'
BSD='_bsd_init'
REGISTER='_sweet_amfi_policy_register'
VFS='_vfsinit'
USER='_bsd_utaskbootstrap'
FLAGS='_santoni_gpu_graphics_dyld_flags'
COLD=tuple('_bsd_init.cold.'+str(i) for i in range(1,6))

def inspection_helpers(names):
    """Bound only the exact startup roots/cold bodies introduced by dyld proof."""
    if FLAGS not in names:return ()
    found={n for n in names if n.startswith('_bsd_init.cold.')}
    if not found<=set(COLD):raise ValueError('unreviewed BSD cold startup helper')
    selected=(BOOT,BSD,*sorted(found))
    if any(len(names.get(n,()))!=1 for n in selected):
        raise ValueError('dyld startup inspection root missing/ambiguous')
    if len({next(iter(names[n])) for n in selected})!=len(selected):
        raise ValueError('dyld startup inspection roots alias')
    return selected

def audit_startup(codes,names):
    from santoni_gpu_launcher_replay import require
    for symbol in (BOOT,BSD,REGISTER,VFS,USER):
        require(len(names.get(symbol,()))==1,'dyld startup symbol missing/ambiguous: '+symbol)
    require(BOOT in codes and BSD in codes,'dyld startup complete caller graphs missing')
    boot,bsd=codes[BOOT],codes[BSD]
    for symbol in (BOOT,BSD):
        require(codes[symbol].symbol==symbol and codes[symbol].entry==next(iter(names[symbol])),
            'dyld startup graph entry/symbol binding differs: '+symbol)
    entry_calls=boot.calls_to(names[BSD])
    require(len(entry_calls)==1,'kernel bootstrap must invoke BSD init exactly once')
    calls={name:bsd.calls_to(names[name]) for name in (VFS,REGISTER,USER)}
    require(all(len(value)==1 for value in calls.values()),'BSD dyld registration/initial-user entry missing or ambiguous')
    vfs,register,user=(calls[name][0] for name in (VFS,REGISTER,USER))
    require(register not in bsd.walk(bsd.entry,exclude={vfs}),'policy registration bypasses VFS initialization')
    require(user not in bsd.walk(bsd.entry,exclude={register}),'initial user-task creation bypasses policy registration')
    require(user not in bsd.walk(bsd.entry,exclude={vfs}),'initial user-task creation bypasses VFS initialization')
    # A root thread must not invoke the normal initial-user bootstrap directly.
    require(not boot.calls_to(names[USER]),'kernel bootstrap bypasses the BSD registration chain')
    return {'success':True,'bootstrap_to_BSD_call':hex(entry_calls[0]),'VFS_init_call':hex(vfs),
        'policy_registration_call':hex(register),'initial_user_bootstrap_call':hex(user),
        'VFS_dominates_registration':True,'registration_dominates_initial_user_bootstrap':True,
        'actual_supplied_instruction_graphs_checked':True,'scheduler_and_platform_returns_verified':False,
        'runtime_dyld_verified':False,'hardware_verified':False}
