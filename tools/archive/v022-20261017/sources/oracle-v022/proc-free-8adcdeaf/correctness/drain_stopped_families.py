import ctypes,json,os,select,signal,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work/private/proc-free-8adcdeaf/correctness')
OUT=ROOT/'families-root-corrected';runner=str(ROOT/'run_family_gates.py');assert (OUT/'PAUSE').is_file()
libc=ctypes.CDLL(None,use_errno=True);fd=libc.inotify_init1(os.O_CLOEXEC);assert fd>=0;assert libc.inotify_add_watch(fd,os.fsencode(OUT),0x80|0x8)>=0
matches=[]
for p in Path('/proc').glob('[0-9]*'):
 try:
  args=(p/'cmdline').read_bytes().split(b'\0');expected=[s.encode() for s in [runner,'--out',str(OUT)]]
  if len(args)>2 and args[1]==expected[0] and expected[1] in args and args[args.index(expected[1])+1]==expected[2]:matches.append((int(p.name),(p/'stat').read_text().split(') ',1)[1].split()[19]))
 except (OSError,IndexError):pass
assert len(matches)<=1,matches
receipt={'reason':'root rejected8adc due resolver4FD regression; no future old-source families','supervisor':matches,'start':time.time()};deadline=time.monotonic()+900
try:
 while matches:
  state=json.loads((OUT/'state.json').read_text())
  if state['state']=='paused-before-family' and not state['active_families']:
   pid,started=matches[0];assert Path('/proc/'+str(pid)+'/stat').read_text().split(') ',1)[1].split()[19]==started
   receipt.update(quiet_state=state,terminated_supervisor_only=pid);os.kill(pid,signal.SIGTERM);break
  if state['state'] in ('failed','complete'):
   receipt['already_terminal']=state;break
  timeout=deadline-time.monotonic();assert timeout>0,'active families did not drain within900s; no forced stop'
  if not select.select([fd],[],[],timeout)[0]:raise TimeoutError('drain deadline; no running family was terminated')
  os.read(fd,65536)
 report=json.loads((OUT/'result.json').read_text());receipt.update(completed_families=len(report['families']),passed_families=sum(r['passed'] for r in report['families']),completed_jobs=sum(r.get('commands',0) for r in report['families']),end=time.time(),status='safely-drained')
finally:
 os.close(fd);(ROOT/'stopped-family-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt),flush=True)
