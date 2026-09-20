from pathlib import Path
import hashlib,json,subprocess,sys
sys.path.insert(0,'tools')
from r101_libubus_paired_report import verify_window
root=Path('private/r101/libubus-client')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
plan_path=Path('docs/reviews/r101-libubus-cpu-plan.json')
plan=json.loads(plan_path.read_text())
assert sha('tools/r101_libubus_paired_cpu.sh')==plan['workload_sha256']
assert sha('private/r101/libubus-client/register-libubus')==plan['benchmark_sha256']
base=[sys.executable,'tools/r95_device_smoke.py','ubusd']
safety=['--recovery-gate','private/r96/recovery-full/recovery-gate.json','--guard','private/r95/guard']
roles={'baseline':Path('private/r95/ubusd-pilot/stock'),'candidate':Path('private/r100/registration-stack/ubusd-rs')}
for block in plan['blocks']:
    slots=block['slots']; out=root/f'cpu-{block["block"]:02d}'
    for role,path in roles.items(): assert sha(path)==plan['subjects'][role]
    control=roles[slots['a']]; candidate=roles[slots['b']]
    subprocess.run(base+[str(candidate),str(out)]+safety+['--before-candidate',str(control),'--pilot','--iterations',str(plan['iterations']),'--workload-script','tools/r101_libubus_paired_cpu.sh','--benchmark','private/r101/libubus-client/register-libubus'],check=True)
    verify_window(out,plan,block)
(root/'COMPLETE').touch()
