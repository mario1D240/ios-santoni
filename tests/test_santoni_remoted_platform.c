/* New contracts for the actual reconstructed workaround and exec boundary. */
#include "santoni_remoted_platform_stubs.h"
#include "santoni_remoted_platform_actual.h"
#undef printf

static struct mount mp;
static struct vnode vp;
static struct cs_blob blob;
static struct proc proc;
static struct _posix_spawnattr attr;
static struct image_params image;
static unsigned completed;

static void reset(void)
{
    memset(&services, 0, sizeof(services));
    memset(&mp, 0, sizeof(mp));
    memset(&vp, 0, sizeof(vp));
    memset(&blob, 0, sizeof(blob));
    memset(&proc, 0, sizeof(proc));
    memset(&image, 0, sizeof(image));
    memset(&attr, 0, sizeof(attr));
    reason_count = 0;
    target = &proc;
    proc.pid = 43;
    memcpy(proc.p_name, "remoted", sizeof("remoted"));
    proc.p_textvp = &vp;
    proc.flags = CS_VALID | CS_SIGNED;
    mp.flags = MNT_ROOTFS;
    vp.type = VREG;
    vp.mount = &mp;
    vp.path = "/usr/libexec/remoted";
    vp.blob = &blob;
    blob.csb_flags = CS_VALID | CS_SIGNED;
    image.ip_flags = IMGPF_SPAWN;
    image.ip_csflags = proc.flags;
    image.ip_vp = &vp;
    image.ip_new_thread = &image;
    attr.psa_platform = PLATFORM_IOS;
    image.ip_px_sa = &attr;
    services.platform = PLATFORM_IOS;
    services.access_error = KERN_SUCCESS;
    services.taskgated_error = KERN_SUCCESS;
    unentitled_ios_sim_launch = false;
    platform_exec_logging = 0;
    santoni_remoted_platform = 1;
    santoni_remoted_platform_logged = 0;
}

static void helper_case(const char *name, bool promote)
{
    struct cs_blob saved = blob;
    uint32_t flags = proc.flags;
    santoni_remoted_platform_exec(&proc);
    assert(proc.flags == (flags | (promote ? CS_PLATFORM_BINARY : 0)));
    assert(services.platform_calls == (unsigned)promote);
    assert(services.flag_updates == (unsigned)promote);
    assert(services.lock_calls == services.unlock_calls && !proc.locked);
    assert(memcmp(&saved, &blob, sizeof(blob)) == 0);
    if (promote) {
        assert(proc.task.platform);
        assert(csproc_get_platform_binary(&proc) == 1);
    }
    printf("PASS helper/%s\n", name);
    completed++;
}

static void helpers(void)
{
    reset(); santoni_remoted_platform = 0; helper_case("default_off", false);
    assert(services.api_calls == 0 && services.log_calls == 0);
    reset(); santoni_remoted_platform = 2; helper_case("optin_two", false);
    assert(services.api_calls == 0);
    reset(); santoni_remoted_platform = UINT32_MAX; helper_case("optin_full_width", false);
    reset(); santoni_remoted_platform_exec(NULL);
    assert(services.api_calls == 0 && services.log_calls == 0);
    printf("PASS helper/null_process\n"); completed++;
    reset(); memcpy(proc.p_name, "launchd", sizeof("launchd")); helper_case("other_process", false);
    reset(); proc.p_textvp = NULL; helper_case("missing_text", false);
    reset(); vp.type = VDIR; helper_case("directory", false);
    reset(); vp.type = VCHR; helper_case("device_vnode", false);
    reset(); vp.mount = NULL; helper_case("missing_mount", false);
    reset(); mp.flags = 0; helper_case("nonroot", false);
    assert(services.path_calls == 0);
    reset(); vp.path = "/private/tmp/remoted"; helper_case("other_root_path", false);
    reset(); vp.path = "/usr/libexec/remoted2"; helper_case("path_suffix", false);
    reset(); vp.path = "/usr/libexec/../libexec/remoted"; helper_case("unresolved_alias", false);
    reset(); vp.path = "/private/preboot/Cryptexes/OS/usr/libexec/remoted";
    helper_case("cryptex_alias_refused", false);
    reset(); vp.path_error = EIO; helper_case("path_error", false);
    reset(); vp.path = "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/remoted";
    helper_case("path_overflow", false);
    reset(); vp.override_length = true; vp.path_length = 0; helper_case("zero_length", false);
    reset(); vp.override_length = true; vp.path_length = -1; helper_case("negative_length", false);
    reset(); vp.override_length = true; vp.path_length = 19; helper_case("short_length", false);
    reset(); vp.override_length = true; vp.path_length = 65; helper_case("oversized_length", false);
    reset(); vp.missing_nul = true; helper_case("missing_nul", false);
    reset(); blob.csb_flags = 0; helper_case("invalid_blob", false);
    reset(); proc.flags |= CS_KILLED; helper_case("killed_exec", false);
    reset(); helper_case("signed_root_missing_platform", true);
    assert(strstr(services.platform_log, "signed=1 blob=1 blob_valid=1 blob_platform=0") != NULL);
    reset(); mp.flags |= MNT_RDONLY; helper_case("readonly_root", true);
    reset(); vp.blob = NULL; helper_case("signed_root_missing_blob", true);
    reset(); proc.flags = CS_VALID; vp.blob = NULL; helper_case("unsigned_root", true);
    assert((proc.flags & CS_SIGNED) == 0);
    assert(strstr(services.platform_log, "csflags=00000001 signed=0 blob=0") != NULL);
    reset(); proc.flags = 0; vp.blob = NULL; helper_case("no_signature_claim", true);
    assert(proc.flags == CS_PLATFORM_BINARY);
    reset(); blob.csb_platform_binary = 1; proc.task.platform = true;
    helper_case("existing_blob_platform", false);
    reset(); proc.flags |= CS_PLATFORM_BINARY; proc.task.platform = true;
    helper_case("existing_exec_platform", false);
    reset(); helper_case("first_exec", true);
    unsigned logs = services.platform_logs;
    santoni_remoted_platform_exec(&proc);
    assert(services.platform_logs == logs && logs == 1);
    assert(services.platform_calls == 1 && santoni_remoted_platform_logged == 1);
    printf("PASS helper/log_once\n"); completed++;
}

static void queries(void)
{
    reset(); proc.flags = CS_PLATFORM_BINARY; santoni_remoted_platform = 0;
    assert(csproc_get_platform_binary(&proc) == 0);
    printf("PASS query/default_off\n"); completed++;
    reset(); proc.flags = CS_PLATFORM_BINARY; santoni_remoted_platform = 2;
    assert(csproc_get_platform_binary(&proc) == 0);
    printf("PASS query/invalid_optin\n"); completed++;
    reset(); proc.flags = CS_PLATFORM_BINARY; vp.blob = NULL;
    assert(csproc_get_platform_binary(&proc) == 1);
    printf("PASS query/exec_local_platform\n"); completed++;
    reset(); proc.flags = CS_PLATFORM_BINARY; proc.p_textvp = NULL;
    assert(csproc_get_platform_binary(&proc) == 0);
    assert(csproc_get_platform_binary(NULL) == 0);
    printf("PASS query/null_text_or_process\n"); completed++;
    reset(); santoni_remoted_platform = 0; blob.csb_platform_binary = 1;
    assert(csproc_get_platform_binary(&proc) == 1);
    printf("PASS query/original_signed_blob\n"); completed++;
    reset(); blob.csb_platform_binary = 0;
    assert(csproc_get_platform_binary(&proc) == 0);
    printf("PASS query/original_nonplatform_blob\n"); completed++;
}

static void exec_case(const char *name, bool success)
{
    struct cs_blob saved = blob;
    int result = process_signature(&proc, &image);
    /* A killed spawn can return zero; it still must not acquire the workaround. */
    assert(result == 0);
    assert(!proc.locked && services.lock_calls == services.unlock_calls);
    assert(memcmp(&saved, &blob, sizeof(blob)) == 0);
    if (success) {
        assert((proc.flags & CS_PLATFORM_BINARY) != 0 && proc.task.platform);
        assert(services.platform_calls == 1 && services.kills == 0);
    } else {
        assert((proc.flags & CS_PLATFORM_BINARY) == 0 && !proc.task.platform);
        assert(services.platform_calls == 0 && services.platform_logs == 0);
        assert(services.kills == 1);
    }
    printf("PASS exec/%s\n", name);
    completed++;
}

static void exec_boundaries(void)
{
    reset(); exec_case("successful_signed_exec", true);
    reset(); image.ip_csflags = 0; vp.blob = NULL; exec_case("successful_unsigned_exec", true);
    assert(proc.flags == CS_PLATFORM_BINARY);
    reset(); image.ip_mac_return = EPERM; exec_case("mac_policy_failure", false);
    reset(); image.ip_cs_error = os_reason_create(1, 1); exec_case("signature_failure", false);
    reset(); services.constraint_error = EACCES; exec_case("launch_constraint_failure", false);
    reset(); services.proc_error = EINVAL; exec_case("machine_signature_failure", false);
    reset(); services.thread_error = KERN_FAILURE; exec_case("thread_signature_failure", false);
    reset(); image.ip_px_sa = NULL; exec_case("missing_ios_platform", false);
    reset(); attr.psa_platform = 7; exec_case("wrong_ios_platform", false);
    reset(); image.ip_csflags = 0; services.access_port = 1;
    services.taskgated_error = KERN_FAILURE; exec_case("taskgated_refusal", false);
    reset(); image.ip_csflags = 0; services.access_port = 1;
    services.taskgated_error = 200; exec_case("taskgated_transport_error", false);
    reset(); image.ip_csflags = 0; vp.blob = NULL;
    services.access_error = KERN_FAILURE; exec_case("no_access_port_unsigned", true);
    reset(); proc.flags |= CS_PLATFORM_BINARY; memcpy(proc.p_name, "launchd", sizeof("launchd"));
    assert(process_signature(&proc, &image) == 0);
    assert(proc.flags == image.ip_csflags && services.platform_calls == 0);
    printf("PASS exec/inherited_platform_cleared\n"); completed++;
    reset(); santoni_remoted_platform = 0;
    assert(process_signature(&proc, &image) == 0);
    assert(proc.flags == image.ip_csflags && services.platform_logs == 0 && services.platform_calls == 0);
    printf("PASS exec/default_off_success\n"); completed++;
}

int main(void)
{
    helpers(); queries(); exec_boundaries();
    printf("Completed %u new remoted platform contracts\n", completed);
    return 0;
}
