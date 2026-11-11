#!/usr/bin/env python3
"""Execute the actual 0220 CI-kernel API with modeled owned memory/callbacks.

This proves prepared mapping/command/cache/fence contracts only. No callback
publishes GPU commands, allocates XNU memory or imports/presents IOSurfaces.
"""
import argparse
import hashlib
import json
from pathlib import Path

from santoni_gpu_binary_model import Machine, integer
from santoni_gpu_launcher_replay import require
from santoni_gpu_scalar_certificate import load_inputs, identity_of
from santoni_gpu_render_audit import HELPERS, prepared_only
from verify_santoni_gpu_render_evidence import verify as verify_native


class RenderModel:
    ARENA, DESC, OPS, PA, TABLES, PIXELS, SOURCE, DESTINATION, COMMANDS, ALIAS = (
        0x61000000, 0x61002000, 0x61003000, 0x61004000, 0x62000000,
        0x63000000, 0x64000000, 0x64001000, 0x64002000, 0x64003000)
    CALLBACKS = {0x71000100: 'read', 0x71000200: 'now', 0x71000300: 'wait',
                 0x71000400: 'clean', 0x71000500: 'invalidate'}
    OWNER = 0x100000001

    def __init__(self, codes, image, names, e):
        self.GVA = 0x01200000 if '_sgpu_render_live_start' in names else 0x01000000
        selected = (*HELPERS, '_sgpu_blit_commands')
        if '_sgpu_packet7' in codes:
            selected += ('_sgpu_packet7',)
        self.e = e
        self.vm = Machine({n: codes[n] for n in selected}, image, names, e)
        self.m = self.vm.memory
        for address, size, fill in ((self.ARENA, 4384, 0), (self.DESC, 88, 0),
                (self.OPS, 120, 0), (self.PA, 32 * 8, 0), (self.TABLES, 7 * 4096, 0x55),
                (self.PIXELS, 32 * 4096, 0xa5), (self.SOURCE, 24, 0),
                (self.DESTINATION, 24, 0), (self.COMMANDS, 400, 0xa5), (self.ALIAS, 8, 0)):
            self.m.map(address, size, fill=fill)
        for offset, value in ((0, self.TABLES), (8, self.PIXELS), (16, self.PA)):
            self.m.put(self.DESC + offset, value, 8)
        for i in range(7): self.m.put(self.DESC + 24 + i * 8, 0x98000000 + i * 4096, 8)
        self.m.put(self.DESC + 80, 32)
        for i in range(32): self.m.put(self.PA + i * 8, 0x98100000 + i * 8192, 8)
        self.m.put(self.OPS, self.ARENA, 8)
        for offset, address in ((16, 0x71000100), (48, 0x71000200), (56, 0x71000300),
                                (80, 0x71000400), (88, 0x71000500)):
            self.m.put(self.OPS + offset, address, 8)
        self.vm.external = self.external
        self.clock, self.ready, self.fence_value = 1000, 1, 0
        self.stopped, self.expired = False, False
        self.status, self.irq, self.cb, self.global_fsr = 0x800001c1, 0, 0x400, 0
        self.cleans, self.invalidates, self.reads, self.waits = [], [], [], 0
        self.fence_reads = 0
        self.m.readonly += [(self.DESC, self.DESC + 88), (self.OPS, self.OPS + 120),
                            (self.PA, self.PA + 256)]

    def change(self, address, value, size=4):
        """Explicit synthetic input mutation, outside execution of kernel words."""
        saved = self.m.readonly
        self.m.readonly = []
        try:
            self.m.put(address, value, size)
        finally:
            self.m.readonly = saved

    def call(self, name, *arguments):
        value = self.vm.run('_sgpu_render_' + name, arguments, budget=2000000)
        require(value is not None and isinstance(value.expr, int), 'render result is not concrete')
        return value.expr

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name not in ('_bzero', '_memcpy', '_memmove', '_memset') and target not in self.CALLBACKS:
            return False
        if probe:
            return True
        a = lambda i: integer(before, 'x' + str(i))
        result = 0
        if name in ('_bzero', '_memcpy', '_memmove', '_memset'):
            length = a(1) if name == '_bzero' else a(2)
            require(0 <= length <= 131072 and self.m.locate(a(0), length) is not None,
                    'render memory primitive escapes modeled owned objects')
            data = self.m.bytes(a(1), length, partial=True) if name in ('_memcpy', '_memmove') else bytes(
                [a(1) & 255 if name == '_memset' else 0]) * length
            self.m.write(a(0), data); result = a(0)
        else:
            require(a(0) == self.ARENA, 'render callback context differs')
            name = self.CALLBACKS[target]
            if name == 'read':
                key = (a(1), a(2)); self.reads.append(key)
                values = {(4, 0x13d4): self.status, (4, 0x1384): self.irq,
                          (5, 0x8058): self.cb, (5, 0x48): self.global_fsr}
                require(key in values, 'unreviewed render MMIO read')
                result = values[key]
            elif name == 'now':
                result = self.clock
            elif name == 'wait':
                require(a(1) == 100, 'render wait is not bounded 100us step')
                self.waits += 1
                if not self.stopped: self.clock += 200000 if self.expired else 100
            else:
                require(self.m.get(self.ARENA + 4364) != 0 and self.m.get(self.ARENA + 4377, 1) == 1,
                        'cache callback precedes exposure/busy bookkeeping')
                require(self.m.locate(a(1), a(2)) is not None and 0 < a(2) <= 7 * 4096,
                        'cache callback escapes owned object/extent')
                (self.cleans if name == 'clean' else self.invalidates).append((a(1), a(2)))
                if name == 'invalidate' and a(1) == self.TABLES + 6 * 4096:
                    require(a(2) == 64, 'render fence cache-line width differs')
                    self.fence_reads += 1
                    if self.ready and self.fence_reads >= self.ready:
                        self.m.put(a(1), self.fence_value or self.m.get(self.ARENA + 4364))
        state.put('x0', self.e._Value(64, result))
        return True

    def prepare(self):
        require(self.call('init', self.ARENA, self.DESC, self.OPS) == 1, 'render init failed')
        for i, address in enumerate((self.SOURCE, self.DESTINATION)):
            handle = self.call('new', self.ARENA, self.OWNER, 4096)
            require(handle == i + 1, 'render initial handle/owner differs')
            for offset, value in ((0, handle), (4, 0), (8, 16), (12, 16), (16, 64), (20, 1)):
                self.m.put(address + offset, value)
        require(self.m.get(self.TABLES + 2 * 4096 + 2 * 8, 8) == 0 and
                self.m.get(self.TABLES + 2 * 4096 + 4 * 8, 8) == 0, 'render guard page mapped')
        self.m.readonly += [(self.SOURCE, self.SOURCE + 24), (self.DESTINATION, self.DESTINATION + 24)]

    def begin(self, owner=None, output=None, capacity=100):
        return self.call('begin', self.ARENA, self.OWNER if owner is None else owner,
                         self.SOURCE, self.DESTINATION, output or self.COMMANDS, capacity)

    def success(self):
        require(self.begin() == 73, 'render builder word count differs')
        require(self.cleans == [(self.TABLES, 28672), (self.PIXELS, 4096),
                (self.PIXELS + 4096, 4096), (self.COMMANDS, 292)], 'render cache publication order/extent differs')
        fixed = self.COMMANDS + 1024
        self.m.map(fixed, 400)
        require(self.vm.run('_sgpu_blit_commands', (fixed, 100, 0x01030300)).expr == 73,
                'fixed A505 builder unavailable')
        words = [self.m.get(fixed + i * 4) for i in range(73)]
        i, changes = 0, 0
        while i < len(words):
            h = words[i]; i += 1
            count = h & (127 if h >> 28 == 4 else 0x3fff)
            if h >> 28 == 4 and (h >> 8) & 0x3ffff in (0x2107, 0x2110):
                source = (h >> 8) & 0x3ffff == 0x2107
                require(words[i + 1] == (0x01040000 if source else 0x01050000), 'fixed base differs')
                words[i + 1] = self.GVA + (4096 if source else 12288); changes += 1
            elif h >> 28 == 7 and (h >> 16) & 0x7f == 0x46:
                require(words[i + 1] == 0x01030300, 'fixed fence address differs')
                words[i + 1] = self.GVA; changes += 1
                if words[i] == 4:
                    require(words[i + 3] == 0xa5052d01, 'fixed fence sequence differs')
                    words[i + 3] = 1; changes += 1
            i += count
        require(changes == 5 and [self.m.get(self.COMMANDS + i * 4) for i in range(73)] == words,
                'render builder changed unreviewed A505 control words')
        require(self.begin() == 0, 'busy render resubmitted')
        require(self.call('cpu', self.ARENA, self.OWNER, 1, 0, 4, self.ALIAS) == 0,
                'busy BO exposed to CPU')
        require(self.call('wait', self.ARENA) == 1 and self.m.get(self.ARENA + 4360) == 1 and
                self.m.get(self.ARENA + 4364) == 0, 'render fence did not finish coherently')
        require(self.invalidates == [(self.TABLES + 24576, 64), (self.PIXELS + 4096, 4096)] and
                self.reads == [(4, 0x13d4), (4, 0x1384), (5, 0x8058), (5, 0x48)],
                'render readback cache/fault/idle checks differ')
        require(self.call('cpu', self.ARENA, self.OWNER, 1, 0, 4, self.ALIAS) == 1 and
                self.m.get(self.ALIAS, 8) == self.PIXELS, 'completed CPU alias wrong')
        require(self.call('new', self.ARENA, self.OWNER, 4096) == 0, 'exposed tables mutated')
        require(self.begin() == 73 and self.call('wait', self.ARENA) == 1 and
                self.m.get(self.ARENA + 4360) == 2, 'distinct repeated fence failed')
        pte = self.m.get(self.TABLES + 8192 + 8, 8)
        require(self.call('free', self.ARENA, self.OWNER, 1) == 0 and
                self.m.get(self.TABLES + 8192 + 8, 8) == pte and self.m.get(self.ARENA + 129, 1) == 1,
                'exposed BO reclaimed instead of quarantined')

    def failure(self, case):
        require(self.begin() == 73, 'render failure setup failed')
        if case == 'stopped-clock': self.ready, self.stopped = 0, True
        elif case == 'expired-clock': self.ready, self.expired = 0, True
        elif case == 'wrong-fence': self.fence_value, self.stopped = 2, True
        elif case == 'busy-engine': self.status, self.stopped = 2, True
        elif case == 'cb-fault': self.cb = 2
        elif case == 'global-fault': self.global_fsr = 8
        elif case == 'irq-fault': self.irq = 0x200
        elif case == 'late-page': self.change(self.PA + 31 * 8, 0, 8)
        elif case == 'late-guard': self.m.put(self.TABLES + 8192 + 4 * 8, 3, 8)
        else: raise ValueError('unknown render failure case')
        require(self.call('wait', self.ARENA) == 0, 'unsafe render fence accepted')
        error = 2 if case.endswith('fault') else 3 if case.startswith('late-') else 1
        require(self.m.get(self.ARENA + 4368) == error and self.m.get(self.ARENA + 4364) == 1 and
                self.m.get(self.ARENA + 4360) == 0 and self.m.get(self.ARENA + 129, 1) == 1 and
                self.m.get(self.ARENA + 169, 1) == 1, 'render first failure/busy/quarantine differs')
        self.vm.run('_sgpu_render_abort', (self.ARENA, 2))
        require(self.m.get(self.ARENA + 4368) == error and self.begin() == 0, 'render first error overwritten')
        if case in ('stopped-clock', 'wrong-fence', 'busy-engine'):
            require(self.fence_reads == 2001 and self.waits == 2000, 'stopped-clock hard cap differs')
        if case == 'expired-clock':
            require(self.fence_reads == 2 and self.waits == 1, 'render clock deadline ignored')


def audit(ci):
    ci = Path(ci).resolve()
    native = Path(__file__).resolve().parents[1] / 'tests/santoni_gpu_render_host_evidence.json'
    require(verify_native(json.loads(native.read_text()))['native_ABI_checked'] is True,
            'render native ABI/source intake missing')
    base, codes, image, names, e = load_inputs(ci)
    require(prepared_only(codes, names) is not None, '0220 prepared render API absent')
    require(all(name in codes for name in HELPERS), '0220 actual word/ISA loader missing')
    identity = {**identity_of(base), 'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    directory = ci / 'render-components'; directory.mkdir(exist_ok=True)
    cases = ('success', 'stopped-clock', 'expired-clock', 'wrong-fence', 'busy-engine',
             'cb-fault', 'global-fault', 'irq-fault', 'late-page', 'late-guard', 'foreign-owner',
             'invalid-stride', 'invalid-size', 'mixed-format', 'missing-page', 'mapped-guard', 'command-alias',
             'capacity', 'sequence-wrap', 'stale-handle', 'full-padded-plane', 'array-pitch-overflow')
    rows = {}
    for case in cases:
        path = directory / (case + '.json')
        if path.exists():
            row = json.loads(path.read_text())
            require(row.get('identity') == identity and row.get('success') is True, 'render receipt identity differs')
            rows[case] = row; continue
        model = RenderModel(codes, image, names, e); model.prepare()
        if case == 'success': model.success()
        elif case in cases[1:10]: model.failure(case)
        elif case in ('full-padded-plane', 'array-pitch-overflow'):
            # This executes the compiled plane arithmetic; it does not claim
            # that the small model BO was mapped as a full-size IOSurface.
            model.m.put(model.ARENA + 108, 4194304)
            for offset, value in ((8, 720 if case == 'full-padded-plane' else 1024),
                    (12, 1280 if case == 'full-padded-plane' else 1024),
                    (16, 3072 if case == 'full-padded-plane' else 4096), (20, 2)):
                model.change(model.SOURCE + offset, value)
            require(model.call('plane_valid', model.SOURCE, model.ARENA + 96) == int(case == 'full-padded-plane'),
                    'full padded/array-pitch plane arithmetic differs')
        else:
            owner, output, capacity = model.OWNER, model.COMMANDS, 100
            if case == 'foreign-owner': owner = 1
            elif case == 'invalid-stride': model.change(model.SOURCE + 16, 320)
            elif case == 'invalid-size': model.change(model.SOURCE + 12, 0xffffffff)
            elif case == 'mixed-format': model.change(model.DESTINATION + 20, 2)
            elif case == 'missing-page': model.m.put(model.TABLES + 8192 + 8, 0, 8)
            elif case == 'mapped-guard': model.m.put(model.TABLES + 8192 + 16, 3, 8)
            elif case == 'command-alias': output = model.TABLES
            elif case == 'capacity': capacity = 99
            elif case == 'sequence-wrap': model.m.put(model.ARENA + 4356, 0xffffffff)
            elif case == 'stale-handle':
                require(model.call('free', model.ARENA, model.OWNER, 1) == 1, 'offline free failed')
                require(model.call('new', model.ARENA, model.OWNER, 4096) == 3, 'stale handle revived')
            arena_before = model.m.bytes(model.ARENA, 4384)
            commands_before = model.m.bytes(model.COMMANDS, 400)
            require(model.begin(owner, output, capacity) == 0 and not model.cleans and
                    model.m.bytes(model.ARENA, 4384) == arena_before and
                    model.m.bytes(model.COMMANDS, 400) == commands_before, 'malformed render request mutated/published')
        row = {'identity': identity, 'success': True, 'visited_words': len(model.vm.visited),
               'callback_calls': len(model.vm.calls), 'fence_reads': model.fence_reads}
        with path.open('x') as stream: stream.write(json.dumps(row, indent=2) + '\n')
        rows[case] = row
        print('Actual prepared render API passed:', case, flush=True)
    record = {**identity, 'success': True, 'hardware_verified': False, 'cases': len(rows), 'results': rows,
              'scope': 'prepared kernel-only contract; memory/cache/MMIO/clock responses modeled; no ring publication',
              'actual_words_A53_checked': True, 'owner_guard_stride_cache_fence_quarantine_checked': True,
              'live_allocator_worker_and_display_integration': False}
    with (ci / 'render-binary-audit.json').open('x') as stream: stream.write(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('ci', type=Path)
    print(json.dumps(audit(parser.parse_args().ci), indent=2))
