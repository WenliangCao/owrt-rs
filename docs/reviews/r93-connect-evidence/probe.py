import socket,subprocess,tempfile,pathlib,time,json,sys
binary=sys.argv[1]; expected=sys.argv[2]
rows=[]
for mode in ('nohello','partialhello','backlog'):
 with tempfile.TemporaryDirectory(prefix='r93-connect-') as td:
  path=td+'/bus.sock'; listener=socket.socket(socket.AF_UNIX);listener.bind(path);listener.listen(0)
  fills=[]
  if mode=='backlog':
   while True:
    s=socket.socket(socket.AF_UNIX);s.setblocking(False)
    try:s.connect(path);fills.append(s)
    except BlockingIOError:s.close();break
  start=time.monotonic();p=subprocess.Popen([binary,path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  conn=None
  if mode!='backlog':
   listener.settimeout(2);conn,_=listener.accept()
   if mode=='partialhello':conn.sendall(b'\0')
  try:
   out,err=p.communicate(timeout=1.6); elapsed=time.monotonic()-start
   rows.append({'case':mode,'elapsed':elapsed,'exit':p.returncode,'stdout':out.strip(),'stderr':err.strip(),'hung':False})
  except subprocess.TimeoutExpired:
   p.kill();p.communicate();rows.append({'case':mode,'elapsed':time.monotonic()-start,'hung':True})
  if conn:conn.close()
  for s in fills:s.close()
  listener.close()
print(json.dumps(rows,indent=2))
assert all(row['hung'] for row in rows) if expected=='red' else all(not row['hung'] and row['exit']==0 and .85<row['elapsed']<1.4 for row in rows)
