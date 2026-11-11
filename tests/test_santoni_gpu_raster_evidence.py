"""Exact native-receipt admission and explicit malformed/surviving challenges."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(os.environ.get('SANTONI_RASTER_EVIDENCE_PROJECT',str(Path(__file__).resolve().parents[1])))
EVIDENCE=Path(os.environ.get('SANTONI_RASTER_EVIDENCE_DIR',str(ROOT/'tests')))
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tools'))
import verify_santoni_gpu_raster_evidence as intake

class RasterEvidenceGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records={kind:json.loads((EVIDENCE/('santoni_gpu_'+name+'_host_evidence.json')).read_text())
            for kind,name in [('ir3','ir3'),('raster','raster'),('bridge','graphics_bridge')]}
        cls.contracts={kind:intake.contract(kind) for kind in cls.records}

    def refused(self,kind,record):
        # Schema challenges share the actual freshly reconstructed contract;
        # the positive test independently performs production reconstruction.
        with patch.object(intake,'contract',return_value=self.contracts[kind]):
            with self.assertRaises(ValueError):intake.verify(record,kind)

    def test_actual_native_receipts(self):
        for kind,positives,negatives in [('ir3',270,75),('raster',153,60),('bridge',423,0)]:
            with self.subTest(kind=kind):
                result=intake.verify(self.records[kind],kind)
                self.assertEqual(result['positive_executions'],positives)
                self.assertEqual(result['compiled_rejected_mutants'],negatives)
                self.assertFalse(result['hardware_verified']);self.assertFalse(result['shader_rendering_verified'])

    def test_scope_hash_and_inventory_refusals(self):
        for kind in self.records:
            for case in ('hardware','success','input','source','omit-row','duplicate-row','compile',
                         'omit-run','failed-positive','input-omission'):
                with self.subTest(kind=kind,case=case):
                    record=copy.deepcopy(self.records[kind]);row=record['rows'][0]
                    if case=='hardware':record['hardware_verified']=True
                    elif case=='success':record['success']=False
                    elif case=='input':record['inputs_sha256'][next(iter(record['inputs_sha256']))]='0'*64
                    elif case=='source':record['source_sha256'][next(iter(record['source_sha256']))]='0'*64
                    elif case=='omit-row':record['rows'].pop()
                    elif case=='duplicate-row':record['rows'][-1]=copy.deepcopy(record['rows'][0])
                    elif case=='compile':row['compile_exit']=1
                    elif case=='omit-run':row['runs'].pop()
                    elif case=='failed-positive':row['runs'][0]['exit_code' if kind=='bridge' else 'exit']=1
                    elif case=='input-omission':record['inputs_sha256'].pop(next(iter(record['inputs_sha256'])))
                    self.refused(kind,record)

    def test_exact_mutant_bytes_case_and_rejection(self):
        for kind in ('ir3','raster'):
            for case in ('survives','wrong-case','wrong-source','classification','missing-variant'):
                with self.subTest(kind=kind,case=case):
                    record=copy.deepcopy(self.records[kind]);row=next(r for r in record['rows'] if r['mutant'])
                    if case=='survives':row['runs'][0]['exit']=0
                    elif case=='wrong-case':row['runs'][0]['case']+=1
                    elif case=='wrong-source':row['source_sha256']='0'*64
                    elif case=='classification':row['mutant']=False
                    elif case=='missing-variant':row['name']='unreviewed-mutation-O2'
                    self.refused(kind,record)

    def test_compile_flags_are_not_just_variant_labels(self):
        for kind in ('ir3','raster'):
            for case in ('warnings','optimization','sanitize'):
                with self.subTest(kind=kind,case=case):
                    record=copy.deepcopy(self.records[kind]);row=next(r for r in record['rows'] if r['name']=='ubsan')
                    if case=='warnings':row['command'].remove('-Werror')
                    elif case=='optimization':row['command'].append('-O3')
                    else:row['command'].append('-fno-sanitize=undefined')
                    self.refused(kind,record)

    def test_uncertainty_and_counters_remain_explicit(self):
        record=copy.deepcopy(self.records['bridge']);record['allocator_VM_begin_modeled']=False
        self.refused('bridge',record)
        record=copy.deepcopy(self.records['raster']);record['transport_refused_after_validation']=False
        self.refused('raster',record)
        for kind in ('ir3','raster'):
            for field in ('native_executions','compiled_rejected_mutants'):
                record=copy.deepcopy(self.records[kind]);record[field]+=1
                self.refused(kind,record)

    def test_bad_variant_name_is_a_clean_refusal(self):
        for kind in self.records:
            record=copy.deepcopy(self.records[kind]);record['rows'][0]['name']=[]
            self.refused(kind,record)

    def test_noninteger_run_case_and_counters_refused(self):
        for kind in ('ir3','raster'):
            record=copy.deepcopy(self.records[kind]);record['native_executions']=float(record['native_executions'])
            self.refused(kind,record)
            record=copy.deepcopy(self.records[kind]);record['rows'][0]['runs'][0]['case']=0.0
            self.refused(kind,record)

if __name__=='__main__':unittest.main()
