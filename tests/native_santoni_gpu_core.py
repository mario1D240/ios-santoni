"""Link real auxiliary modules without changing historical core reconstructions."""
import hashlib
from pathlib import Path
import shutil
import tempfile
from tests.reconstruct_santoni_touch import reconstruct as reconstruct_base

VM='bsd/dev/santoni_gpu_vm.c'

def reconstruct(output,through=None,targets=None):
    result=reconstruct_base(output,through=through,targets=targets)
    output=Path(output)
    dev=output/'bsd/dev'
    dependencies={}
    if (dev/'santoni_gpu_core.c').is_file() and (dev/'santoni_gpu_vm.h').is_file():
        destination=output/VM
        if not destination.is_file():
            preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
            with tempfile.TemporaryDirectory(prefix='native-gpu-core-dep-',dir=preferred if preferred.is_dir() else None) as temporary:
                source=Path(temporary)/'source'
                auxiliary=reconstruct_base(source,through=through,targets=(VM,))
                # It is the same ordered patch chain and same local headers,
                # not an extracted substitute or a separately guessed VM ABI.
                for name,want in auxiliary['dependencies'].items():
                    path=output/name
                    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=want:
                        raise ValueError('native VM/header reconstruction differs: '+name)
                shutil.copyfile(source/VM,destination)
        dependencies[VM]=hashlib.sha256(destination.read_bytes()).hexdigest()
    result['native_link_dependencies']=dependencies
    return result

def core_link_dependencies(dev):
    dev=Path(dev)
    if not (dev/'santoni_gpu_vm.h').is_file():return []
    module=dev/'santoni_gpu_vm.c'
    if not module.is_file():raise ValueError('real native VM link module missing')
    return [str(module)]

def core_source_hashes(result):
    return {**result['sha256'],**result['native_link_dependencies']}
