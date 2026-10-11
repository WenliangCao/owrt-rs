#!/usr/bin/env python3
import argparse,json,os,struct,sys,subprocess,time,hashlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('candidate',type=Path);p.add_argument('out',type=Path);a=p.parse_args()
sys.path.insert(0,str(a.source/'tools/dnsmasq'))
from m2_rootfs import prepare,command,sha256
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
a.out.mkdir()
image=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
root=prepare(image,None,a.out/'image',a.candidate)
result={'tool_sha256':sha256(Path(__file__)),'scope':'independent C/R actual mappings; image filesystem and isolated host kernel; no router','variants':{}}
for variant,relative in [('c','usr/sbin/dnsmasq'),('rust','usr/sbin/dnsmasq-rs')]:
    binary=root/relative;data=binary.read_bytes(); etype=struct.unpack_from('<H',data,16)[0]
    phoff=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
    ph=[struct.unpack_from('<IIQQQQQQ',data,phoff+i*size) for i in range(count)]
    relro=next(row for row in ph if row[0]==0x6474e552)
    readelf=subprocess.check_output(['readelf','-W','-h','-l','-d',str(binary)],text=True)
    (a.out/f'{variant}.readelf').write_text(readelf)
    item={'sha256':sha256(binary),'size':binary.stat().st_size,'elf_type':etype,'relro_vaddr':relro[3],'relro_memsz':relro[6],'runs':[]}
    for i in range(3):
        pid=root/'m2/protection.pid';pid.unlink(missing_ok=True)
        argv=command(root,variant,'-C','/dev/null','-k','--user=root','--group=root','--port=0','--no-hosts','--no-resolv','--pid-file=/m2/protection.pid','--log-facility=-')
        with (a.out/f'{variant}-{i}.log').open('wb') as log:
            process=subprocess.Popen(argv,stdout=log,stderr=log)
            try:
                limit=time.monotonic()+5
                while not pid.exists():
                    assert process.poll() is None and time.monotonic()<limit
                    time.sleep(.01)
                maps=Path(f'/proc/{process.pid}/maps').read_text();(a.out/f'{variant}-{i}.maps').write_text(maps)
                assert sha256(Path(f'/proc/{process.pid}/exe'))==sha256(binary)
                entries=[]
                for line in maps.splitlines():
                    fields=line.split();start,end=(int(x,16) for x in fields[0].split('-'))
                    entries.append((start,end,fields[1],fields))
                mapped=next(start for start,end,perm,f in entries if f[-1]==str(binary) and int(f[2],16)==0)
                bias=mapped if etype==3 else 0;begin=(bias+relro[3])&~4095;end=(bias+relro[3]+relro[6])&~4095
                pages=[{'address':hex(page),'permissions':next(perm for low,high,perm,f in entries if low<=page and high>=page+4096)} for page in range(begin,end,4096)]
                smaps=Path(f'/proc/{process.pid}/smaps_rollup').read_text()
                (a.out/f'{variant}-{i}.smaps').write_text(smaps)
                item['runs'].append({'base':hex(mapped),'relro_pages':pages,'relro_readonly':bool(pages) and all('w' not in x['permissions'] for x in pages),'stack_permissions':next(perm for low,high,perm,f in entries if f[-1]=='[stack]'),'wx_mappings':[f for low,high,perm,f in entries if 'w' in perm and 'x' in perm],'mapped_files':sorted({f[-1] for _,_,_,f in entries if f[-1].startswith('/')})})
            finally:
                if process.poll() is None:process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            assert process.returncode==0
    item['distinct_bases']=len({r['base'] for r in item['runs']});result['variants'][variant]=item
(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
