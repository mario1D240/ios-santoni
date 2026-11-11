"""Actual 0223 UI import/ring/fence and framebuffer lifetime contracts.

MMIO/cache/IOKit are host models. These tests do not prove hardware UI output.
"""
import json
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
from tests.test_santoni_gpu_prepare import source_function

ROOT = Path(__file__).resolve().parents[1]
FILES = ('bsd/dev/santoni_gpu.c','bsd/dev/santoni_gpu_core.c',
         'bsd/dev/santoni_gpu_core.h','iokit/Kernel/arm/SweetFramebuffer.cpp')
VARIANTS = (('O0',['-O0']),('O2',['-O2']),
            ('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))


def model_header():
    text=(ROOT/'tests/test_santoni_gpu_live.c').read_text().split('int main(',1)[0]
    text=text.replace('uint8_t *tables_dma, *pixels_dma;', '''uint8_t *tables_dma, *pixels_dma;
    uint8_t *import_cpu[2], *import_dma[2];
    uint64_t import_pa[2][SGPU_RENDER_BYTES/SGPU_PAGE];
    bool ui; unsigned wraps;
    uint64_t source_tlb[SGPU_RENDER_BYTES/SGPU_PAGE];''')
    text=text.replace('delta[10]','delta[4096]').replace('m->live_writes<10','m->live_writes<4096')
    text=text.replace('static uint8_t *live_physical', '''static uint8_t *live_import_physical(struct live_model *m,uint64_t pa,uint32_t bytes)
{
    for(unsigned b=0;b<2;b++) for(unsigned i=0;i<SGPU_RENDER_BYTES/SGPU_PAGE;i++)
        if(m->import_dma[b] && pa>=m->import_pa[b][i] && pa-m->import_pa[b][i]<SGPU_PAGE) {
            unsigned off=(unsigned)(pa-m->import_pa[b][i]); assert(bytes<=SGPU_PAGE-off);
            return m->import_dma[b]+i*SGPU_PAGE+off;
        }
    return NULL;
}
static uint8_t *live_physical''',1)
    text=text.replace('uint8_t *old=physical(&m->session.base,pa,bytes);',
                      'uint8_t *old=live_import_physical(m,pa,bytes); if(old)return old; old=physical(&m->session.base,pa,bytes);',1)
    text=text.replace('uint64_t pte=table[(va>>shift[level])&511];', '''uint64_t pte=table[(va>>shift[level])&511];
        if(level==2 && m->ui && va>=SGPU_RENDER_VA+SGPU_PAGE &&
            va<SGPU_RENDER_VA+SGPU_PAGE+SGPU_RENDER_BYTES)
            pte=m->source_tlb[(va-SGPU_RENDER_VA-SGPU_PAGE)/SGPU_PAGE];''',1)
    text=text.replace('assert(end==b->last+73 &&', 'assert((end==b->last+73 || (end==73 && end<b->last)) &&',1)
    text=text.replace('off==SG_RB_WPTR && value==b->last+73',
                      'off==SG_RB_WPTR && (value==b->last+73 || (m->ui && value==73 && value<b->last))',1)
    text=text.replace('for(unsigned i=b->last;i<end;) {', '''unsigned first=b->last;
    if(end<first) {
        assert(ring[first]==sgpu_packet7(0x10,SGPU_PAGE/4-first-1));
        for(unsigned i=first+1;i<SGPU_PAGE/4;i++)assert(!ring[i]);
        first=0;m->wraps++;
    }
    for(unsigned i=first;i<end;) {''',1)
    text=text.replace('static void live_write(void *ctx', 'static void live_write(void *ctx',1)
    text=text.replace('assert(value==0x1126 || value==0x1127);', '''assert(value==0x1126 || value==0x1127);
        if(m->ui && value==0x1126) {m->tlbi=false;m->sync=false;m->status_reads=0;}''',1)
    text=text.replace('m->sync=true;', '''m->sync=true;
        if(m->ui) {
            const uint64_t *table=(const uint64_t *)(const void *)(m->tables_dma+2*SGPU_PAGE);
            for(unsigned i=0;i<SGPU_RENDER_BYTES/SGPU_PAGE;i++)m->source_tlb[i]=table[1+i];
        }''',1)
    text=text.replace('b->last=end;*reg(b,SG_GPU,SG_RB_RPTR)=end;*reg(b,SG_GPU,SG_STATUS)=0;', '''b->last=end;*reg(b,SG_GPU,SG_RB_RPTR)=end;*reg(b,SG_GPU,SG_STATUS)=0;
    if(m->ui && m->injection==37)*reg(b,SG_GPU,SG_STATUS)=2;''',1)
    text=text.replace('uint8_t *s=live_address(m,sva,n,false),*d=live_address(m,dva,n,true);', '''uint8_t *s=live_address(m,sva,n,false),*d=live_address(m,dva,n,true);
                        if(m->ui)assert(!live_address(m,sva,n,true));''',1)
    text=text.replace('m->full_blits++;', '''m->full_blits++;
                if(m->ui) {
                    assert(!live_address(m,SGPU_RENDER_VA+961*SGPU_PAGE,4,false));
                    assert(!live_address(m,SGPU_RENDER_VA+1922*SGPU_PAGE,4,false));
                }''',1)
    text=text.replace('} else session_clean(&m->session,p,n);', '''} else {
        for(unsigned b=0;b<2;b++) if(m->import_cpu[b] && ptr>=(uintptr_t)m->import_cpu[b] &&
            ptr-(uintptr_t)m->import_cpu[b]<SGPU_RENDER_BYTES) {
            unsigned off=(unsigned)(ptr-(uintptr_t)m->import_cpu[b]);
            assert(n<=SGPU_RENDER_BYTES-off);memcpy(m->import_dma[b]+off,p,n);return;
        }
        session_clean(&m->session,p,n);
    }''',1)
    # All replacements describe external hardware behavior; production C is untouched.
    return text


class UIContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='ui0223-',dir=preferred if preferred.is_dir() else None)
        cls.root=Path(cls.temp.name)
        draft=os.environ.get('SANTONI_UI_SOURCE')
        if draft:
            cls.dev=Path(draft)/'bsd/dev'
            cls.fb=(Path(draft)/FILES[-1]).read_text()
        else:
            cls.manifest=reconstruct(cls.root/'source',targets=FILES)
            cls.dev=cls.root/'source/bsd/dev'
            cls.fb=(cls.root/'source'/FILES[-1]).read_text()
        cls.core=(cls.dev/'santoni_gpu_core.c').read_text()
        cls.adapter=(cls.dev/'santoni_gpu.c').read_text()
        cls.identity={'core_sha256':hashlib.sha256(cls.core.encode()).hexdigest(),
            'adapter_sha256':hashlib.sha256(cls.adapter.encode()).hexdigest(),
            'framebuffer_sha256':hashlib.sha256(cls.fb.encode()).hexdigest()}
        cls.inputs={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
            ('tests/test_santoni_gpu_ui.py','tests/test_santoni_gpu_ui.c',
             'tests/test_santoni_gpu_ui_adapter.c','tests/test_santoni_gpu_ui_framebuffer.cpp',
             'tests/test_santoni_gpu_live.c','tests/test_santoni_gpu_live_adapter.c',
             'tests/test_santoni_gpu_session.c')}
        (cls.root/'santoni_gpu_session_model.h').write_text(
            (ROOT/'tests/test_santoni_gpu_session.c').read_text().split('static bool boot_session(',1)[0])
        (cls.root/'santoni_gpu_live_ui_model.h').write_text(model_header())
        cls.rows=[]

    @classmethod
    def tearDownClass(cls):
        evidence=os.environ.get('SANTONI_UI_NATIVE_RESULT')
        if evidence: Path(evidence).write_text(json.dumps({'identity':cls.identity,
            'inputs':cls.inputs,'rows':cls.rows},indent=2)+'\n')
        cls.temp.cleanup()

    def native(self,name,flags,source=None,cases=range(20),positive=True):
        folder=self.root/name;folder.mkdir()
        actual=folder/'santoni_gpu_core.c';actual.write_text(source or self.core)
        binary=folder/'test'
        args=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11',*flags,
              '-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
              '-I',str(self.dev),'-I',str(self.root),'-I',str(ROOT/'tests'),
              str(ROOT/'tests/test_santoni_gpu_ui.c'),str(actual),
              *core_link_dependencies(self.dev),'-o',str(binary)]
        built=subprocess.run(args,capture_output=True,text=True,timeout=90)
        row={'name':name,'command':args,'compile_exit':built.returncode,
             'source_sha256':hashlib.sha256(actual.read_bytes()).hexdigest(),
             'compile_stderr':built.stderr,'runs':[]};self.rows.append(row)
        self.assertEqual(built.returncode,0,built.stderr)
        for case in cases:
            ran=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=60)
            row['runs'].append({'case':case,'exit':ran.returncode,'stdout':ran.stdout,'stderr':ran.stderr})
            if positive:self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            else:self.assertNotEqual(ran.returncode,0,'compiled unsafe mutant survived: '+name)

    def test_actual_UI_core(self):
        for name,flags in VARIANTS:self.native(name,flags)

    def test_actual_framebuffer_presentation_and_holds(self):
        start=self.fb.index('#if defined(SANTONI)\n/* Narrow shared C ABI:')
        end=self.fb.index('bool\nAppleCLCD::gpuPresent(',start)
        header='\n\n'.join((source_function(self.fb,'get32'),
            source_function(self.fb,'sweet_bgra_to_bgr24'),self.fb[start:end],
            source_function(self.fb,'AppleCLCD::gpuPresent'),
            source_function(self.fb,'AppleCLCD::gpuRestoreShadow'),'#endif',
            source_function(self.fb,'AppleCLCD::blitPanel'),
            source_function(self.fb,'AppleCLCD::present')))
        header=header.replace('__asm__ volatile("dsb sy" ::: "memory");','barriers++;')
        self.assertNotIn('__asm__',header)
        (self.root/'santoni_gpu_ui_framebuffer_actual.h').write_text(header)
        for name,flags in VARIANTS:
            binary=self.root/('framebuffer-'+name)
            args=[*shlex.split(os.environ.get('HOST_CXX','clang++')),'-std=c++14',*flags,
                '-Wall','-Wextra','-Werror','-I',str(self.root),
                str(ROOT/'tests/test_santoni_gpu_ui_framebuffer.cpp'),'-o',str(binary)]
            built=subprocess.run(args,capture_output=True,text=True,timeout=90)
            row={'name':'framebuffer-'+name,'command':args,'compile_exit':built.returncode,
                 'compile_stderr':built.stderr,'runs':[]};self.rows.append(row)
            self.assertEqual(built.returncode,0,built.stderr)
            for case in range(20):
                ran=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=30)
                row['runs'].append({'case':case,'exit':ran.returncode,'stdout':ran.stdout,'stderr':ran.stderr})
                self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)

    def test_actual_adapter_options_publication_and_each_pmap(self):
        from tests.test_santoni_gpu_live import adapter_header
        prefix=(ROOT/'tests/test_santoni_gpu_live_adapter.c').read_text().split('#include "santoni_gpu_live_adapter_actual.h"',1)[0]
        begin=prefix.index('/* This legacy worker harness')
        end=prefix.index('static unsigned testcase',begin)
        prefix=prefix[:begin]+prefix[end:]
        prefix=prefix.replace('static ppnum_t pmap_find_phys',
            'static uintptr_t ui_fixture_source;\nstatic ppnum_t pmap_find_phys',1)
        needle='assert(pmap==kernel_pmap);translations++;'
        prefix=prefix.replace(needle,needle+'''
    if(ui_fixture_source && va>=ui_fixture_source && va-ui_fixture_source<SGPU_RENDER_BYTES) {
        unsigned i=(unsigned)((va-ui_fixture_source)/SGPU_PAGE);
        return testcase==8 && i==959?0:(ppnum_t)((0xa3000000ull+i*2*SGPU_PAGE)>>12);
    }''',1)
        prefix=prefix.replace('else if(!strcmp(name,"santonigpu_ui"))value=0;',
            'else if(!strcmp(name,"santonigpu_ui"))value=testcase==1 || (testcase>=21 && testcase<24)?0:testcase==2?2:1;',1)
        (self.root/'santoni_gpu_ui_adapter_model.h').write_text(prefix)
        (self.root/'santoni_gpu_live_adapter_actual.h').write_text(adapter_header(self.adapter,self.core))
        for name,flags in VARIANTS:
            binary=self.root/('adapter-'+name)
            args=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11',*flags,
                '-Wall','-Wextra','-Werror','-I',str(self.dev),'-I',str(self.root),
                str(ROOT/'tests/test_santoni_gpu_ui_adapter.c'),'-o',str(binary)]
            built=subprocess.run(args,capture_output=True,text=True,timeout=90)
            row={'name':'adapter-'+name,'command':args,'compile_exit':built.returncode,
                 'compile_stderr':built.stderr,'runs':[]};self.rows.append(row)
            self.assertEqual(built.returncode,0,built.stderr)
            for case in range(25):
                ran=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=30)
                row['runs'].append({'case':case,'exit':ran.returncode,'stdout':ran.stdout,'stderr':ran.stderr})
                self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)

    def test_legacy_functions_unchanged(self):
        old=Path(os.environ['SANTONI_UI_BASELINE']) if 'SANTONI_UI_BASELINE' in os.environ else None
        if old: baseline=(old/'bsd/dev/santoni_gpu_core.c').read_text()
        else:
            reconstruct(self.root/'previous',through=222,targets=FILES[:3])
            baseline=(self.root/'previous/bsd/dev/santoni_gpu_core.c').read_text()
        for name in ('sgpu_render_live_start','sgpu_render_live_link','sgpu_render_live_job',
                     'sgpu_render_begin','sgpu_render_wait','sgpu_session_start','sgpu_session_execute'):
            self.assertEqual(source_function(baseline,name),source_function(self.core,name))

    def test_compiling_UI_mutants(self):
        mutants=(
            ('late-pa','sgpu_ui_image_valid','pa<SGPU_DMA_MIN','false',2),
            ('duplicate','sgpu_ui_image_valid','if (pa==s->pa[j]) return false;','if (false) return false;',3),
            ('table-alias','sgpu_ui_image_valid','if (sgpu_ui_reserved(pa)) return false;','if (sgpu_ui_reserved(pa) && false) return false;',4),
            ('owned-change','sgpu_ui_memory_valid','if (m->pa[i]!=sgpu_ui.owned_pa[i]) return false;','if (false) return false;',19),
            ('report-isolation','sgpu_ui_start','p->report = &sgpu_ui.report;','(void)p;',11),
            ('stop','sgpu_ui_remap','!checked_write32(p,SG_GPU,SG_ME_CNTL,SG_CP_LIVE_READBACK_MASK,SG_CP_STOP_MASK)','false',0),
            ('route','sgpu_ui_remap','!checked_write32(p,SG_SMMU,SG_S2CR0,~0u,SG_S2CR_FAULT)','false',0),
            ('tlbi','sgpu_ui_remap','!checked_write32(p,SG_SMMU,SG_CB_TLBIASID,0,1)','false',0),
            ('readonly','sgpu_ui_remap','l3[source->first+i]=sgpu_ui.pa[i]|PTE_RO;','l3[source->first+i]=sgpu_ui.pa[i]|PTE_RW;',0),
            ('fence','sgpu_ui_wait','*(volatile uint32_t *)(void *)fence==a->busy','true',10),
            ('cpu-cache','sgpu_ui_wait','p->ops->invalidate(p->ops->ctx,a->memory.pixels+a->bo[1].physical*SGPU_PAGE,SGPU_RENDER_BYTES);','(void)p;',0),
            ('wrap','sgpu_ui_submit','ring[pos]=sgpu_packet7(0x10,remain-1);','ring[pos]=0;',0),
        )
        for name,fn,old,new,case in mutants:
            body=source_function(self.core,fn);self.assertEqual(body.count(old),1,name)
            changed=self.core.replace(body,body.replace(old,new,1),1)
            self.native('mutant-'+name,['-O2'],changed,(case,),False)


if __name__=='__main__': unittest.main()
