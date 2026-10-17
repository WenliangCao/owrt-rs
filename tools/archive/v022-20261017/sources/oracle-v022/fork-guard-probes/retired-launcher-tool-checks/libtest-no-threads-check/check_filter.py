from pathlib import Path
import hashlib, json, re
path=Path('tools/dnsmasq/libtest_no_threads.c')
text=path.read_text()
body=text.split('struct sock_filter filter[] = {',1)[1].split('\n    };',1)[0]
const={'BPF_LD':0, 'BPF_W':0, 'BPF_ABS':0x20, 'BPF_JMP':5, 'BPF_JEQ':0x10, 'BPF_K':0,
       'BPF_RET':6, 'BPF_ALU':4, 'BPF_AND':0x50, 'BPF_JSET':0x40,
       'SECCOMP_RET_KILL_PROCESS':0x80000000, 'SECCOMP_RET_ALLOW':0x7fff0000,
       'SECCOMP_RET_ERRNO':0x50000, 'ENOSYS':38, 'EAGAIN':11, 'CLONE_THREAD':0x10000}
counts={}
for arch, audit, clone in [('x86_64',0xc000003e,56),('aarch64',0xc00000b7,220)]:
    code=body
    if arch=='aarch64':
        code=re.sub(r'#if defined\(__x86_64__\).*?#endif','',code,flags=re.S)
    code=re.sub(r'/\*.*?\*/','',code,flags=re.S)
    for name,offset in [('arch',4),('nr',0),('args[0]',16)]:
        code=code.replace('offsetof(struct seccomp_data, '+name+')',str(offset))
    values=dict(const,TEST_AUDIT_ARCH=audit,__NR_clone3=435,__NR_clone=clone)
    instructions=[]
    for kind,args in re.findall(r'BPF_(STMT|JUMP)\((.*?)\),',code,re.S):
        parts=[eval(re.sub(r'\b(0x[0-9a-fA-F]+|\d+)U\b',r'\1',item),{'__builtins__':{}},values) for item in args.split(',')]
        instructions.append((parts[0],parts[2] if kind=='JUMP' else 0,
                             parts[3] if kind=='JUMP' else 0,parts[1]&0xffffffff))
    def run(observed_arch,nr,flags):
        pc=acc=0
        data={0:nr,4:observed_arch,16:flags&0xffffffff}
        while pc<len(instructions):
            op,jt,jf,k=instructions[pc]
            if op==0x20: acc=data[k]
            elif op==0x15: pc+=jt if acc==k else jf
            elif op==0x45: pc+=jt if acc&k else jf
            elif op==0x54: acc &= k
            elif op==0x06: return k
            else: raise AssertionError(('unknown BPF op',op))
            pc+=1
        raise AssertionError('missing terminal return')
    checks=0
    syscall_numbers=list(range(1024))+[-1,0xffffffff]
    if arch=='x86_64': syscall_numbers += [number|0x40000000 for number in range(1024)]
    for nr in syscall_numbers:
        for flags in [0,17,0x4111,0x10000,0x10011,0x100000000,0x100010000]:
            normalized=(nr&0xffffffff)&(~0x40000000&0xffffffff) if arch=='x86_64' else nr&0xffffffff
            expected=0x50000|38 if normalized==435 else 0x50000|11 if normalized==clone and flags&0x10000 else 0x7fff0000
            assert run(audit,nr&0xffffffff,flags)==expected,(arch,nr,flags)
            checks+=1
    for other in [0x40000003,0xc000003e,0xc00000b7,0]:
        if other!=audit:
            assert run(other,clone,0)==0x80000000
            checks+=1
    counts[arch]={'instructions':len(instructions),'synthetic_decisions':checks}
report={'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'checks':counts,
        'scope':'Offline evaluator of source BPF macros only; no Linux compile, kernel filter, Rust build, or target execution'}
Path('private/libtest-no-threads-check/filter.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
