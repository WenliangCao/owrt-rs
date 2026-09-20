from pathlib import Path
import hashlib,json,subprocess,sys
root=Path('private/r102/event-fanout')
plan=json.loads(Path('docs/reviews/r102-event-fanout-plan.json').read_text())
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
paths={'stock':Path('private/r95/ubusd-pilot/stock'),'r89':Path('private/r95/ubusd-pilot/r89'),'before':Path('private/r100/event-epoch/ubusd-rs'),'candidate':Path('private/r100/registration-stack/ubusd-rs')}
assert sha('tools/r95_device_smoke.py')==plan['source_scripts']['tools/r95_device_smoke.py']
assert sha('tools/benchmark/isolated.sh')==plan['source_scripts']['tools/benchmark/isolated.sh']
assert sha('tools/r98_registration_watch.sh')==plan['source_scripts']['tools/r98_registration_watch.sh']
assert sha('private/r98/event-client/owrt-benchmark')==plan['benchmark_sha256']
for block in plan['blocks']:
    for side in block['order']:
        assert sha(paths[side])==plan['subjects'][side]
        name=f"{block['block']:02d}-{side}"
        print('START',name,flush=True)
        subprocess.run([sys.executable,'tools/r95_device_smoke.py','ubusd',str(paths[side]),str(root/name),'--recovery-gate','private/r96/recovery-full/recovery-gate.json','--guard','private/r95/guard','--pilot','--iterations',str(plan['iterations']),'--implementation','c' if side=='stock' else 'rs','--workload-script','tools/r98_registration_watch.sh','--benchmark','private/r98/event-client/owrt-benchmark'],check=True)
(root/'COMPLETE').touch()
