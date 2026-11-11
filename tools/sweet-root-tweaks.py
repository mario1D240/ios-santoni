#!/usr/bin/env python3
"""Apply the SWEET bring-up changes to an iOS root made by tools/mkiosroot.sh.

  sudo sweet-root-tweaks.py MOUNTED_ROOT [--migrate-extensions]

MOUNTED_ROOT is the HFS+ image mounted read-write (Linux: run
`fsck.hfsplus -fy` on the image, then `mount -t hfsplus -o loop,force`).
Run as root (it writes root/mobile owned files). Idempotent. This is what
turned the plain mkiosroot.sh output into the images that reach the home
screen in the inherited root image variants:

  launchd.plist   _PanicOnCrash -> _PanicOnCrasX (a crashing daemon must not
                  panic the system); CommCenter jobs removed (no baseband: it
                  crash-loops and Setup blocks on its CoreTelephony XPC)
  containers      /private/var/containers/{Bundle,Data/System,Shared/SystemGroup,Temp}
                  (on iOS they live on the data volume)
  migration       preserved by default; --migrate-extensions explicitly requests
                  first-boot extension migration. Automatic migration is disabled
                  after a reported loading-bar regression in the Santoni rebuild.
  feature flags   ExtensionKit enforce_xpc_cache_code_signing off for extension
                  definitions whose detached signature needs unavailable trust
                  caches (the sailfish root setup uses this same override)
  audio           VirtualAudio HAL plug-in disabled (mediaserverd crash)
  MediaToolbox    StartRecorderServer=false (camera filter prewarm calls a
                  NULL OpenGL function without a GPU -> mediaserverd crash loop)
  SpringBoard     BKNoWatchdogs (one slow CPU path, no scene-create watchdog
                  kills), no cloud-configuration UI
  Setup           skipped: SetupDone, SetupFinishedAllSteps, SetupVersion 11,
                  mini-buddy flags off
  activation      mobileactivationd data ark seeded; the actual Activated state
                  comes from its Hactivation branch, selected by the /chosen
                  security-status properties in tools/mkadt.py
"""
import argparse, glob, os, plistlib, shutil, sys

BUILD, VERSION = '20H392', '16.7.16'
MOBILE = 501


def load(path):
    with open(path, 'rb') as f:
        return plistlib.load(f)


def save(path, data, uid, gid, mode, fmt=plistlib.FMT_BINARY):
    with open(path, 'wb') as f:
        plistlib.dump(data, f, fmt=fmt)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def merge_pref(root, name, values):
    """Merge keys into /var/mobile/Library/Preferences/NAME.plist (mobile, 0600)."""
    path = os.path.join(root, 'private/var/mobile/Library/Preferences', name + '.plist')
    data = load(path) if os.path.exists(path) else {}
    data.update(values)
    save(path, data, MOBILE, MOBILE, 0o600)
    print('pref', name, sorted(values))


def launchd(root):
    path = os.path.join(root, 'System/Library/xpc/launchd.plist')
    st = os.stat(path)
    plist = load(path)
    jobs = plist['LaunchDaemons']
    renamed = 0
    for job in jobs.values():
        if '_PanicOnCrash' in job:
            job['_PanicOnCrasX'] = job.pop('_PanicOnCrash')
            renamed += 1
    removed = [k for k, j in jobs.items() if j.get('Label') == 'com.apple.CommCenter']
    for k in removed:
        del jobs[k]
    save(path, plist, st.st_uid, st.st_gid, st.st_mode & 0o7777)
    print(f'launchd.plist: {renamed} _PanicOnCrash renamed, {len(removed)} CommCenter jobs removed')


def containers(root):
    base = os.path.join(root, 'private/var/containers')
    for sub, uid in (('Bundle', 33), ('Data/System', 0), ('Shared/SystemGroup', 0), ('Temp', 0)):
        d = os.path.join(base, sub)
        if not os.path.isdir(d):
            os.makedirs(d)
            os.chown(d, uid, uid)
            os.chmod(d, 0o755)
            print('mkdir', d)


def find_container(root, kind, identifier):
    for meta in glob.glob(os.path.join(root, 'private/var/containers', kind, '*',
                                       '.com.apple.mobile_container_manager.metadata.plist')):
        if load(meta).get('MCMMetadataIdentifier') == identifier:
            return os.path.dirname(meta)
    return None


def activation(root):
    c = find_container(root, 'Data/System', 'com.apple.mobileactivationd')
    if c is None:
        print('warning: no mobileactivationd system container in the image; skipped data ark')
        return
    d = os.path.join(c, 'Library/internal')
    os.makedirs(d, exist_ok=True)
    os.chown(d, MOBILE, MOBILE)
    os.chmod(d, 0o755)
    save(os.path.join(d, 'data_ark.plist'), {
        '-ActivationState': 'Activated', '-BrickState': False,
        '-BuildVersion': BUILD, '-ProductVersion': VERSION,
        '-DataMigrationCompleted': True, '-PreSydroDataMigrationCompleted': True,
    }, MOBILE, MOBILE, 0o600)
    print('data ark', d)


def feature_flags(root):
    directory = os.path.join(root, 'private/var/preferences/FeatureFlags/Domain')
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, 'ExtensionKit.plist')
    data = load(path) if os.path.exists(path) else {}
    if not isinstance(data, dict):
        raise ValueError('ExtensionKit preferences must be a dictionary')
    policy = data.setdefault('enforce_xpc_cache_code_signing', {})
    if not isinstance(policy, dict):
        raise ValueError('ExtensionKit code-signing feature must be a dictionary')
    policy['Enabled'] = False
    save(path, data, 0, 0, 0o644, plistlib.FMT_XML)
    print('feature flag ExtensionKit/enforce_xpc_cache_code_signing off')


def migration(root):
    path = os.path.join(root, 'private/var/mobile/Library/Preferences/com.apple.migration.plist')
    if os.path.exists(path):
        data = load(path)
        if not isinstance(data, dict):
            raise ValueError('migration preferences must be a dictionary')
        disposition = data.get('DMUserDataDisposition')
        synthetic = (data.get('LastSystemVersion') == BUILD and
                     isinstance(disposition, dict) and
                     set(disposition) == {'SyntheticDidUpgrade', 'buildVersion'} and
                     disposition['SyntheticDidUpgrade'] is False and
                     disposition['buildVersion'] == BUILD)
        if synthetic:
            # Exact record written by the previous version of this tool.
            # Keep unrelated preferences and the existing file's metadata.
            st = os.stat(path)
            del data['LastSystemVersion']
            del data['DMUserDataDisposition']
            save(path, data, st.st_uid, st.st_gid, st.st_mode & 0o7777)
            print('removed synthetic completed migration record')
        elif 'LastSystemVersion' in data:
            print('preserved existing migration state; no forced migration')
            return
    sentinel = os.path.join(root, 'private/var/datamigrator/migrate')
    os.makedirs(os.path.dirname(sentinel), exist_ok=True)
    if not os.path.exists(sentinel):
        with open(sentinel, 'xb'):
            pass
        os.chown(sentinel, MOBILE, MOBILE)
        os.chmod(sentinel, 0o644)
        print('requested first-boot extension migration')


def audio(root):
    src = os.path.join(root, 'Library/Audio/Plug-Ins/HAL/VirtualAudio.plugin')
    dst_dir = os.path.join(root, 'Library/Audio/Plug-Ins/HAL.disabled')
    if os.path.exists(src):
        os.makedirs(dst_dir, exist_ok=True)
        shutil.move(src, dst_dir)
        print('VirtualAudio.plugin disabled')
    for conf in glob.glob(os.path.join(root, 'System/Library/Frameworks/MediaToolbox.framework/*/SubServerConfiguration.plist')):
        st = os.stat(conf)
        data = load(conf)
        data['StartRecorderServer'] = False
        save(conf, data, st.st_uid, st.st_gid, st.st_mode & 0o7777, plistlib.FMT_XML)
        print('StartRecorderServer off', os.path.relpath(conf, root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root')
    parser.add_argument('--migrate-extensions', action='store_true',
                        help='explicitly request first-boot DataMigration; default preserves existing migration state')
    args = parser.parse_args()
    root = args.root
    if not os.path.isdir(os.path.join(root, 'System/Library/xpc')):
        parser.error('mounted root lacks System/Library/xpc')
    launchd(root)
    containers(root)
    activation(root)
    feature_flags(root)
    if args.migrate_extensions:
        migration(root)
    audio(root)
    merge_pref(root, 'com.apple.springboard', {
        'BKNoWatchdogs': True,
        'FBLaunchWatchdogExceptions': {'com.apple.purplebuddy': 100.0},
        'MCForceShowCloudConfigurationUI': False})
    merge_pref(root, 'com.apple.purplebuddy', {
        'SetupDone': True, 'SetupFinishedAllSteps': True, 'SetupVersion': 11,
        'daemonizeNeedsToRun': False})
    merge_pref(root, 'com.apple.purplebuddy.notbackedup', {
        k: False for k in ('ShouldRunDiagnosticsMiniBuddy', 'ShouldRunHSA2MiniBuddy',
                           'ShouldRunKeychainSyncMiniBuddy', 'ShouldRunMesaMiniBuddy',
                           'ShouldRunPaymentMiniBuddy', 'ShouldRunStandardMiniBuddy',
                           'SilentICDPUpgrade')})
    merge_pref(root, 'com.apple.managedconfiguration.notbackedup', {
        'LockdownActivationIndicatesCloudConfigurationAvailable': False})


if __name__ == '__main__':
    main()
