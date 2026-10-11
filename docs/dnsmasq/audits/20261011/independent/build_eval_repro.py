#!/usr/bin/env python3
import json,os,subprocess,sys,tempfile,hashlib
from pathlib import Path
root=Path.cwd();recipe=root/'packaging/openwrt/owrt-dnsmasq/Makefile'
results={}
with tempfile.TemporaryDirectory() as temp:
    fixture=Path(temp);(fixture/'rules.mk').touch();(fixture/'bin').mkdir()
    compiler=fixture/'bin/aarch64-openwrt-linux-musl-gcc';compiler.write_text('#!/bin/sh\nexit 99\n');compiler.chmod(0o755)
    cargo=fixture/'bin/cargo';cargo.write_text('#!'+sys.executable+'\nimport json,os\nprint(json.dumps({x:os.environ.get(x) for x in ["DNSMASQ_STATIC_PIE_CC","CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"]}))\n');cargo.chmod(0o755)
    env=dict(os.environ,PATH=str(fixture/'bin')+os.pathsep+os.environ['PATH'])
    args=['make','--no-print-directory','-f',str(recipe),'TOPDIR='+str(fixture),'INCLUDE_DIR='+str(fixture),'PKG_BUILD_DIR='+str(fixture/'build'),'V1_CARGO='+str(cargo),'TARGET_CC_NOCACHE='+compiler.name,'TARGET_LINKER=bfd']
    (fixture/'package.mk').write_text('')
    (fixture/'direct.mk').write_text('check:\n\t$(Build/Compile)\n')
    for label,extra in [('direct',['-f',str(fixture/'direct.mk')]),('BuildPackage-eval',[])]:
        if label=='BuildPackage-eval':(fixture/'package.mk').write_text('define BuildPackage\ncheck:\n\t$(Build/Compile)\nendef\n')
        result=subprocess.run([*args,*extra,'check'],cwd=recipe.parent,env=env,text=True,capture_output=True)
        rows=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        results[label]={'returncode':result.returncode,'environment':rows[-1] if rows else None,'stdout':result.stdout,'stderr':result.stderr}
print(json.dumps({'recipe_sha256':hashlib.sha256(recipe.read_bytes()).hexdigest(),'results':results},indent=2))
