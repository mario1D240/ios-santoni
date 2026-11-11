/* Actual extracted XNU VFS_MOUNT/vfs_64bitready and mockfs registration.
 * Host mount/thread contracts only; no kernel or GPU execution. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct mount *mount_t;
typedef void *vnode_t;
typedef uintptr_t user_addr_t;
typedef void *vfs_context_t;
struct vfsops {
    int (*vfs_mount)(mount_t, vnode_t, user_addr_t, vfs_context_t);
};
struct sysctl_oid;
#define MFSNAMELEN 16
#include "vfstable_under_test.inc"
struct mount {
    const struct vfsops *mnt_op;
    struct vfstable *mnt_vtable;
};
_Static_assert(offsetof(struct vfstable, vfc_vfsflags) == 64, "actual LP64 vfstable ABI");
#define ENOTSUP 45
#define MOCKFS 1
#define VFC_VFSGENERICARGS 0x004
#define VFC_VFS64BITREADY 0x100
#define VFC_VFSREADDIR_EXTENDED 0x080
#define MNT_LOCAL 0x1000
#define FT_MOCKFS 0x6d6f636b
static struct mount live_mount, dead_mount;
static mount_t dead_mountp = &dead_mount;
static int context64, callbacks, callback_error, bad_arguments;
static int device_token, context_token;
static vnode_t expected_device;
static vfs_context_t expected_context;
static const user_addr_t expected_data = UINT64_C(0x5566778899aabbcc);
static int callback(mount_t mp, vnode_t dev, user_addr_t data, vfs_context_t ctx)
{
    callbacks++;
    if (mp != &live_mount || dev != expected_device || data != expected_data || ctx != expected_context)
        bad_arguments = 1;
    return callback_error;
}
static int mockfs_mountroot(mount_t mp, vnode_t vp, vfs_context_t ctx)
{ (void)mp; (void)vp; (void)ctx; return 0; }
static const struct vfsops mockfs_vfsops = { callback };
static int vfs_context_is64bit(vfs_context_t ctx)
{ return ctx == expected_context ? context64 : -1; }
#include "vfs_functions_under_test.inc"
static struct vfstable source_registration[] = {
#include "mockfs_registration_under_test.inc"
};

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const char *name = argv[1];
#ifdef ARM64_BOARD_CONFIG_SANTONI
    const int wanted_flags = 0x104;
#else
    const int wanted_flags = 0x004;
#endif
    struct vfstable registration = source_registration[0];
    struct vfsops missing = { NULL };
    live_mount = (struct mount){ &mockfs_vfsops, &registration };
    expected_device = &device_token; expected_context = &context_token;
    context64 = 1;
    int expected = 0, wanted_callbacks = 1;
    mount_t mount = &live_mount;
    if (!strcmp(name, "registration")) {
        if (registration.vfc_vfsflags != wanted_flags || strcmp(registration.vfc_name, "mockfs") ||
            registration.vfc_typenum != FT_MOCKFS || registration.vfc_flags != MNT_LOCAL ||
            registration.vfc_vfsops != &mockfs_vfsops || registration.vfc_mountroot != mockfs_mountroot)
            return 1;
        printf("PASS registration flags=%x\n", registration.vfc_vfsflags);
        return 0;
    } else if (!strcmp(name, "registered64")) {
        if (!(wanted_flags & VFC_VFS64BITREADY)) { expected = ENOTSUP; wanted_callbacks = 0; }
    } else if (!strcmp(name, "registered32")) {
        context64 = 0;
    } else if (!strcmp(name, "callee-error")) {
        registration.vfc_vfsflags = 0x104; callback_error = expected = 5;
    } else if (!strcmp(name, "wrong-ready-bit")) {
        registration.vfc_vfsflags = 0x084; expected = ENOTSUP; wanted_callbacks = 0;
    } else if (!strcmp(name, "generic-only64")) {
        registration.vfc_vfsflags = 0x004; expected = ENOTSUP; wanted_callbacks = 0;
    } else if (!strcmp(name, "missing-callback")) {
        registration.vfc_vfsflags = 0x104; live_mount.mnt_op = &missing;
        expected = ENOTSUP; wanted_callbacks = 0;
    } else if (!strcmp(name, "dead-mount")) {
        mount = dead_mountp; expected = ENOTSUP; wanted_callbacks = 0;
    } else if (!strcmp(name, "unrelated-flags")) {
        registration.vfc_vfsflags = 0x1104;
    } else return 2;
    int result = VFS_MOUNT(mount, expected_device, expected_data, expected_context);
    if (result != expected || callbacks != wanted_callbacks || bad_arguments) {
        fprintf(stderr, "FAIL %s result=%d callbacks=%d bad_arguments=%d\n", name, result, callbacks, bad_arguments);
        return 1;
    }
    printf("PASS %s result=%d callbacks=%d\n", name, result, callbacks);
    return 0;
}
