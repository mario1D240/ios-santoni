#!/usr/bin/env python3
"""Generate typed iOS GLI wrappers using matched20H392 slots and Mesa prototypes."""
import argparse
import hashlib
import json
from pathlib import Path
import re

SLOTS=1036
LAYOUT_SHA256='2766fbc0f49cfdae10eee4b7c86622aab75cd24939c4584ff09a71500f4a26e9'
ALIASES={
    'glCreateShaderObjectARB':'glCreateShader','glCreateProgramObjectARB':'glCreateProgram',
    'glUseProgramObjectARB':'glUseProgram','glAttachObjectARB':'glAttachShader',
    'glDetachObjectARB':'glDetachShader','glGetIntegerIndexedv':'glGetIntegeri_v',
    'glCopyTextureLevels':'glCopyTextureLevelsAPPLE','glPointSizePointer':'glPointSizePointerOES',
    'glGetShaderPrecisionFormatOES':'glGetShaderPrecisionFormat',
    'glReleaseShaderCompilerOES':'glReleaseShaderCompiler','glShaderBinaryOES':'glShaderBinary',
    'glDiscardFramebufferEXT':'glInvalidateFramebuffer',
    'glStencilOpSeparateATI':'glStencilOpSeparate',
}
# ATI's two function enums are front/back functions, unlike the core face/func
# pair. Matching argument count and types does not establish equivalence.
DENY_ALIASES={'glStencilFuncSeparateATI'}
PRIVATE_PROTOTYPES={
    # 20H392 Exec/PackThread inspect two w arguments and one pointed-to w.
    'glFramebufferParameterivAPPLE':('void',[('GLenum','target'),('GLenum','pname'),('const GLint *','params')]),
    'glGetFramebufferParameterivAPPLE':('void',[('GLenum','target'),('GLenum','pname'),('GLint *','params')]),
    # ExecThread preserves x0..x3 only; gleLabelObjectWithResponsibleProcess
    # uses w1 as object type, x2 as a hash name, and stores w3 at object+0x1c.
    # This is process attribution, not the string-label API. No string is read.
    'glLabelObjectWithResponsibleProcessAPPLE':('void',[('GLenum','object'),('GLuint','name'),('GLint','process')]),
}
SPECIAL={name:'sgfx_ui_'+name[2:] for name in (
    'glDeleteObjectARB','glGetObjectParameterivARB','glGetInfoLogARB','glGetAttachedObjectsARB',
    'glGetHandleARB','glFlush','glFinish','glFinishObjectAPPLE','glTestObjectAPPLE',
    'glBindTexture','glDeleteTextures','glTexImage2D','glTexSubImage2D','glTexParameteri',
    'glFramebufferTexture2DEXT','glBindFramebufferEXT','glShaderSourceARB','glLinkProgramARB',
    'glDrawArrays','glDrawElements','glDrawArraysInstanced','glDrawElementsInstanced',
    'glClear','glClearBufferiv','glClearBufferuiv','glClearBufferfv','glClearBufferfi',
    'glDrawRangeElements','glGetString','glGetError','glGetIntegerv','glDeleteFramebuffersEXT',
    *PRIVATE_PROTOTYPES)}

def prototypes(text):
    out={}
    for m in re.finditer(r'(?:GLAPI|GL_API|GL_APICALL)\s+([\w\s*]+?)\s*(?:GLAPIENTRY|APIENTRY|GL_APIENTRY)\s+(gl\w+)\s*\(([^)]*)\)',text):
        result,name,args=m.groups();params=[] if args.strip() in ('','void') else [p.strip() for p in args.split(',')]
        parsed=[]
        for param in params:
            match=re.fullmatch(r'(.+?)([A-Za-z_]\w*)',param)
            if not match:raise ValueError('unhandled parameter declaration: '+param)
            parsed.append((match[1].strip(),match[2]))
        value=(result.strip(),parsed)
        def canonical_type(typ):
            for old,new in (('GLvoid','void'),('GLclampf','GLfloat'),('GLclampd','GLdouble'),
                            ('GLcharARB','GLchar'),('GLintptrARB','GLintptr'),('GLsizeiptrARB','GLsizeiptr')):
                typ=re.sub(r'\b'+old+r'\b',new,typ)
            return re.sub(r'\s+','',typ)
        def shape(proto):return (canonical_type(proto[0]),tuple(canonical_type(t) for t,_n in proto[1]))
        if name in out and shape(out[name])!=shape(value):raise ValueError('ambiguous GL prototype: '+name)
        out.setdefault(name,value)
    return out

def conversion(value,source,destination):
    if source==destination:return value
    def pointer(t):return '*' in t or t in ('GLhandleARB','GLsync')
    if pointer(source)!=pointer(destination):return '('+destination+')(uintptr_t)('+value+')'
    return '('+destination+')('+value+')'

def generate(layout,headers,symbols):
    if hashlib.sha256(layout.encode()).hexdigest()!=LAYOUT_SHA256:
        raise ValueError('GLI layout differs from the verified20H392 metadata')
    slots={}
    for line in layout.splitlines():
        if not line.strip():continue
        i,name=line.split();index=int(i)
        if not 0<=index<SLOTS or index in slots:raise ValueError('invalid/duplicate GLI slot')
        if not re.fullmatch(r'(gl\w+|gliNoop)',name):raise ValueError('invalid GLI name')
        slots[index]=name
    if len(slots)!=410:raise ValueError('expected410 matched20H392 named slots')
    proto=prototypes(headers)
    for name,value in PRIVATE_PROTOTYPES.items():
        if name in proto and proto[name]!=value:raise ValueError('private prototype changed: '+name)
        proto[name]=value
    for name,target in ALIASES.items():
        if name not in proto and target in proto:proto[name]=proto[target]
    defined={row[-1][1:] for row in (line.split() for line in symbols.splitlines())
             if len(row)>=3 and row[-2] in ('T','t') and row[-1].startswith('_gl')}
    functions=[];table=[];unavailable=[];missing_prototypes=[];hand=[]
    for index in range(SLOTS):
        name=slots.get(index)
        if not name:
            table.append('(void *)sgfx_ui_invalid');continue
        if name=='gliNoop':table.append('(void *)sgfx_ui_noop');continue
        if name not in proto:
            missing_prototypes.append(name);table.append('NULL');continue
        if name in SPECIAL:
            table.append('(void *)'+SPECIAL[name]);hand.append(name);continue
        result,params=proto[name]
        targets=[ALIASES.get(name,re.sub(r'(ARB|EXT|OES|APPLE|NV)$','',name)),name]
        target=next((t for t in targets if t in defined and t in proto),None) if name not in DENY_ALIASES else None
        decl=', '.join(['void *context']+[typ+' '+n for typ,n in params])
        fail='return;' if result=='void' else 'return ('+result+')0;'
        bind='if(!sgfx_ui_bind(context)) {'+fail+'}'
        if target:
            returned,tparams=proto[target]
            if len(params)!=len(tparams):raise ValueError('GLI argument count mismatch: '+name+' -> '+target)
            args=[]
            for (typ,n),(t,_tn) in zip(params,tparams):
                value='sgfx_ui_target(context,'+n+')' if n in ('target','textarget') else n
                args.append(conversion(value,typ,t))
            call=target+'('+','.join(args)+')'
            body=call+';' if result=='void' else 'return '+conversion(call,returned,result)+';'
            checks=['if((uintptr_t)'+n+'>UINT32_MAX) {sgfx_ui_unsupported(context,'+str(index)+');'+fail+'}'
                    for (typ,n),(t,_tn) in zip(params,tparams) if typ=='GLhandleARB' and t=='GLuint']
            bind+=''.join(checks)
        else:
            unavailable.append(name);body='sgfx_ui_unsupported(context,'+str(index)+');'+fail
            # Keep exact signatures even when a function is unavailable.
            body=''.join('(void)'+n+';' for _typ,n in params)+body
        functions.append('static '+result+' wrap_'+str(index)+'('+decl+') {'+bind+body+'}')
        table.append('(void *)wrap_'+str(index))
    if missing_prototypes:raise ValueError('GLI prototypes require explicit adapters: '+','.join(sorted(missing_prototypes)))
    text='/* Generated typed GLI20H392 dispatch; not a hardware certificate. */\n#include "ui_dispatch.h"\n\n'
    text+='\n'.join(functions)+'\n\nvoid *const sgfx_ui_dispatch['+str(SLOTS)+']={\n'
    text+=''.join('    '+entry+',\n' for entry in table)+'};\n'
    return text,{'slots':SLOTS,'named_slots':len(slots),'typed_wrappers':len(functions),
                 'manual_adapters':sorted(set(hand)),'unavailable':unavailable,
                 'layout_sha256':hashlib.sha256(layout.encode()).hexdigest(),'hardware_verified':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--layout',type=Path,required=True)
    p.add_argument('--mesa-include',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    headers='\n'.join((a.mesa_include/name).read_text() for name in
        ('GL/gl.h','GL/glext.h','GLES/gl.h','GLES/glext.h','GLES2/gl2.h','GLES2/gl2ext.h','GLES3/gl3.h'))
    generated,record=generate(a.layout.read_text(),headers,a.symbols.read_text())
    receipt=a.output.with_suffix('.json')
    if a.output.exists() or receipt.exists():raise ValueError('refusing to overwrite dispatch or receipt')
    with a.output.open('x') as f:f.write(generated)
    with receipt.open('x') as f:f.write(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))
if __name__=='__main__':main()
