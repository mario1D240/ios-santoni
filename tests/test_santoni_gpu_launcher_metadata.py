"""New checked allocation-data intake; completed launcher suites are not replayed."""
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_santoni_gpu_kernel as kernel
import santoni_gpu_launcher_audit as audit


def section(name, owner, address, size, offset, alignment, flags):
    return struct.pack('<16s16s2Q8I', name, owner, address, size, offset,
                       alignment, 0, 0, flags, 0, 0, 0)


def segment(name, address, size, offset, protection, sections):
    return struct.pack('<II16s4Q4I', 0x19, 72 + 80 * len(sections), name,
                       address, size, offset, size, protection, protection,
                       len(sections), 0) + b''.join(sections)


class Fixture:
    def __init__(self):
        commands = [
            segment(b'__TEXT', 0x1000, 0x1000, 0, 1, [
                section(b'__cstring', b'__TEXT', 0x1800, 0x80, 0x800, 0, 2)]),
            segment(b'__DATA_CONST', 0x3000, 0x1000, 0x1000, 1, [
                section(b'__kalloc_type', b'__DATA_CONST', 0x3400, 128, 0x1400, 3, 0)]),
            segment(b'__TEXT_EXEC', 0x5000, 0x5000, 0x2000, 5, [
                section(b'__text', b'__TEXT_EXEC', 0x5000, 0x5000, 0x2000, 2, 0x80000400)])]
        header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, len(commands),
                             sum(map(len, commands)), 0, 0)
        self.data = bytearray(0x7000)
        self.data[:len(header) + sum(map(len, commands))] = header + b''.join(commands)
        self.text_segment = 32
        self.metadata_segment = 32 + len(commands[0])
        self.text_section = self.text_segment + 72
        self.metadata_section = self.metadata_segment + 72
        names = (*audit.PUBLIC, *audit.DATA, *audit.CALLBACKS, *audit.CHANGED, *audit.TRACE_HELPERS)
        self.names = {name: {0x5000 + 128 * index} for index, name in enumerate(names)}
        self.names.update(dict(zip(audit.ALLOCATION_DATA, ({0x3400}, {0x3440}))))
        for address in (0x3400, 0x3440):
            self.write(address, struct.pack('<5Q2I2Q', 0, 0, 0x1800, 0, 0x1840, 0x64, 72, 0, 0))
        self.write(0x1800, b'site.struct mockfs_mount\0')
        self.write(0x1840, b'221222222\0')

    def write(self, address, data):
        offset = address - 0x1000 if address < 0x2000 else address - 0x3000 + 0x1000
        self.data[offset:offset + len(data)] = data

    def word(self, address, value, size=8):
        self.write(address, value.to_bytes(size, 'little'))

    def image(self):
        return kernel._Image(bytes(self.data))


class AllocationMetadata(unittest.TestCase):
    def test_diagnostic_namespace_loads_reviewed_code_and_keeps_data_separate(self):
        fixture = Fixture()
        fixture.names.update({name: {0xb000 + i * 128} for i, name in
                              enumerate((*audit.DIAG_PUBLIC, *audit.DIAG_HELPERS, *audit.DIAG_DATA))})
        loaded = []
        with patch.object(audit, 'allocation_data', return_value={'success': True}):
            self.assertTrue(audit.load_launcher(loaded.append, {}, fixture.names, image=fixture.image()))
        self.assertTrue(set(audit.DIAG_PUBLIC + audit.DIAG_HELPERS) <= set(loaded))
        self.assertTrue(set(audit.DIAG_DATA).isdisjoint(loaded))
        for name in audit.DIAG_PUBLIC + audit.DIAG_DATA:
            partial = dict(fixture.names); del partial[name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                audit.load_launcher(lambda _: None, {}, partial, image=fixture.image())

    def reject(self, fixture, message=None, image=None, codes=None):
        loaded = []
        with self.assertRaises(ValueError) as caught:
            audit.load_launcher(loaded.append, {} if codes is None else codes, fixture.names,
                                image=fixture.image() if image is None else image)
        self.assertEqual(loaded, [], 'metadata rejection must precede executable loading')
        if message:
            self.assertIn(message, str(caught.exception))

    def test_exact_data_records_are_checked_without_loading_them_as_code(self):
        fixture = Fixture()
        loaded, evidence = [], {}
        self.assertIs(audit.load_launcher(loaded.append, {}, fixture.names,
                                         image=fixture.image(), data_evidence=evidence), True)
        self.assertEqual([r['symbol'] for r in evidence['records']], list(audit.ALLOCATION_DATA))
        self.assertIs(evidence['success'], True)
        self.assertTrue(all(r['kt_size'] == 72 and r['bytes'] == 64 for r in evidence['records']))
        self.assertTrue(set(audit.PUBLIC + audit.CALLBACKS + audit.CHANGED + audit.TRACE_HELPERS) <= set(loaded))
        self.assertTrue(set(audit.ALLOCATION_DATA).isdisjoint(loaded))

    def test_metadata_requires_an_image_and_cannot_already_be_loaded_code(self):
        fixture = Fixture()
        with self.assertRaisesRegex(ValueError, 'needs a data image'):
            audit.load_launcher(lambda _: None, {}, fixture.names)
        self.reject(fixture, 'cannot be executable code', codes={audit.ALLOCATION_DATA[0]: object()})

    def test_unknown_or_partial_metadata_and_function_names_still_reject(self):
        for replacement in (None, '_mockfs_santoni_mount.kalloc_type_view_83',
                            '_mockfs_santoni_mount.kalloc_type_view_60.cold.1'):
            with self.subTest(replacement=replacement):
                fixture = Fixture()
                values = fixture.names.pop(audit.ALLOCATION_DATA[1])
                if replacement:
                    fixture.names[replacement] = values
                self.reject(fixture)
        for name in ('_mockfs_santoni_extra', '_sgpu_launch_extra', '_santoni_gpu_user_launch_extra'):
            with self.subTest(name=name):
                fixture = Fixture()
                fixture.names[name] = {0x9000}
                self.reject(fixture, 'namespace')

    def test_ambiguous_unaligned_overlapping_and_aliased_data_reject(self):
        for values in ({0x3400, 0x3480}, {0x3404}):
            fixture = Fixture()
            fixture.names[audit.ALLOCATION_DATA[0]] = values
            self.reject(fixture)
        for address in (0x3400, 0x3408, 0x3438):
            fixture = Fixture()
            fixture.names[audit.ALLOCATION_DATA[1]] = {address}
            self.reject(fixture, 'aliased or overlapping')
        for name in (audit.PUBLIC[0], audit.DATA[0], '_unrelated_alias'):
            fixture = Fixture()
            fixture.names[name] = {0x3410}
            self.reject(fixture, 'aliased or overlapping')

    def test_writable_executable_and_wrong_data_sections_reject(self):
        for protection in (0, 3, 5, 7):
            fixture = Fixture()
            struct.pack_into('<I', fixture.data, fixture.metadata_segment + 60, protection)
            self.reject(fixture, 'section/protection')
        for offset, value in ((0, b'__text'), (16, b'__TEXT_EXEC')):
            fixture = Fixture()
            struct.pack_into('<16s', fixture.data, fixture.metadata_section + offset, value)
            self.reject(fixture, 'section/protection')
        for flags in (1, 0x80000000, 0x400):
            fixture = Fixture()
            struct.pack_into('<I', fixture.data, fixture.metadata_section + 64, flags)
            self.reject(fixture, 'section/protection')

    def test_whole_record_section_and_file_bounds_are_required(self):
        for size in (63, 127):
            fixture = Fixture()
            struct.pack_into('<Q', fixture.data, fixture.metadata_section + 40, size)
            self.reject(fixture)
        fixture = Fixture()
        struct.pack_into('<I', fixture.data, fixture.metadata_section + 48, 0x1408)
        self.reject(fixture, 'section/protection')
        fixture = Fixture()
        struct.pack_into('<I', fixture.data, fixture.metadata_section + 52, 13)
        self.reject(fixture, 'section/protection')
        fixture = Fixture()
        fixture.names[audit.ALLOCATION_DATA[1]] = {0x3ff0}
        self.reject(fixture)

    def test_partial_section_and_segment_overlaps_reject(self):
        fixture = Fixture()
        image = fixture.image()
        # A section claiming only the final eight metadata bytes still aliases
        # the record; looking only for whole-record matches would miss this.
        command = image.data[32:32 + 152]
        extra = bytearray(command)
        struct.pack_into('<Q', extra, 72 + 32, 0x3438)
        struct.pack_into('<Q', extra, 72 + 40, 8)
        header = bytearray(image.data)
        count, size = struct.unpack_from('<II', header, 16)
        header[32 + size:32 + size + len(extra)] = extra
        struct.pack_into('<II', header, 16, count + 1, size + len(extra))
        image.data = bytes(header)
        self.reject(fixture, 'section extent', image=image)
        image = fixture.image()
        image.segs.append({'vmaddr': 0x3438, 'vmsize': 8, 'filesize': 8, 'initprot': 5})
        self.reject(fixture, 'section/protection', image=image)

    def test_runtime_zone_fields_flags_and_type_size_are_pinned(self):
        for offset in (0, 8, 24, 48, 56):
            fixture = Fixture()
            fixture.word(0x3400 + offset, 1)
            self.reject(fixture, 'initializer/type size')
        for offset, value in ((40, 4), (40, 0x80000064), (44, 56), (44, 80)):
            fixture = Fixture()
            fixture.word(0x3440 + offset, value, 4)
            self.reject(fixture, 'initializer/type size')

    def test_type_name_signature_and_terminating_bytes_are_pinned(self):
        for address, contents in ((0x1800, b'site.struct mockfs_other\0'),
                                  (0x1840, b'221222223\0'), (0x1849, b'x')):
            fixture = Fixture()
            fixture.write(address, contents)
            self.reject(fixture, 'name/signature')
        for offset, pointer in ((16, 0), (32, 0x187c), (32, 0x5000)):
            fixture = Fixture()
            fixture.word(0x3400 + offset, pointer)
            self.reject(fixture)

    def test_strings_require_readonly_cstring_storage(self):
        for protection in (3, 5):
            fixture = Fixture()
            struct.pack_into('<I', fixture.data, fixture.text_segment + 60, protection)
            self.reject(fixture, 'section/protection')
        fixture = Fixture()
        struct.pack_into('<I', fixture.data, fixture.text_section + 64, 0)
        self.reject(fixture, 'section/protection')

    def test_missing_and_truncated_section_bytes_fail_closed(self):
        fixture = Fixture()
        for data in (b'', fixture.image().data[:40]):
            image = fixture.image()
            image.data = data
            self.reject(fixture, image=image)
        image = fixture.image()
        data = bytearray(image.data)
        struct.pack_into('<I', data, fixture.metadata_segment + 64, 2)
        image.data = bytes(data)
        self.reject(fixture, 'section table', image=image)

    def test_unreadable_record_or_pointed_to_string_rejects(self):
        fixture = Fixture()
        for blocked in (0x3400, 0x1840):
            image = fixture.image()
            original = image.read
            image.read = lambda address, size: None if address == blocked else original(address, size)
            self.reject(fixture, 'not fully file-backed', image=image)


if __name__ == '__main__':
    unittest.main()
