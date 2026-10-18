import json,sys,time
from pathlib import Path
from types import SimpleNamespace
from odhcpd_baseline import Fixture,FABLE_PROVIDER,network_input
out=Path("/home/ubuntu/odhcpd-validation-20261018/fable-provider-selftest-01")
out.mkdir(mode=0o700)
f=Fixture(SimpleNamespace(rootfs="/home/ubuntu/owrt-v023-20261017/private/native-final-0a925bcc/rootfs",out=str(out),daemon=None,case="fable-instrument",provider_shape="typed"))
try:
 f.setup();f.provider.terminate();f.provider.wait(3)
 (f.root/"tmp/provider.uc").write_text(FABLE_PROVIDER)
 state={"network":network_input(),"delay_ms":250,"version":42}
 (f.root/"tmp/fable-state.json").write_text(json.dumps(state))
 compiled=f.chroot("/usr/bin/ucode","-c","/tmp/provider.uc","-o","/tmp/provider.ucb")
 f.start_provider()
 start=time.monotonic();r=f.bus("network.interface","dump");elapsed=time.monotonic()-start
 assert json.loads(r["stdout"])==state["network"]
 assert elapsed>=.20 and elapsed<2
 stats=json.loads(f.bus("fixture","stats")["stdout"])
 assert stats["calls"]==stats["completed"]==1 and stats["pending"]==0 and stats["version"]==42
 f.bus("fixture","notify",{"interface":"wan"})
 print(json.dumps({"python_syntax":"passed","ucode_compile":"passed","delayed_provider":"passed","elapsed_s":elapsed,"stats":stats,"product_daemon_started":False},indent=2))
finally:f.close()
