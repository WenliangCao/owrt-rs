from pathlib import Path
import hashlib,json,subprocess,sys
root=Path('private/r103-event-send-borrow/fanout');plan=json.loads(Path('docs/reviews/r103-event-send-fanout-plan.json').read_text());sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
paths={'stock':Path('private/r95/ubusd-pilot/stock'),'r89':Path('private/r95/ubusd-pilot/r89'),'before':Path('private/r100/registration-stack/ubusd-rs'),'candidate':Path('private/r103-event-send-borrow/ubusd-rs')}
for block in plan['blocks']:
 for side in block['order']:
  out=root/f'{block["block"]:02d}-{side}';assert sha(paths[side])==plan['subjects'][side]
  subprocess.run([sys.executable,'tools/r95_device_smoke.py','ubusd',str(paths[side]),str(out),'--recovery-gate','private/r96/recovery-full/recovery-gate.json','--guard','private/r95/guard','--pilot','--iterations',str(plan['iterations']),'--implementation','c' if side=='stock' else 'rs','--workload-script','tools/r98_registration_watch.sh','--benchmark','private/r98/event-client/owrt-benchmark'],check=True)
(root/'COMPLETE').touch()
