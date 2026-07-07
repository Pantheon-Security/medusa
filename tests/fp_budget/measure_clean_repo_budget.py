import subprocess, tempfile, json, glob, os, collections
REPOS = ["psf/black","pallets/jinja","pallets/flask","tiangolo/typer","encode/starlette",
         "Textualize/rich","psf/requests","pallets/click","sqlalchemy/alembic","chalk/chalk"]
print(f"{'repo':26} {'CRIT':>5} {'HIGH':>5} {'MED':>5} {'MED+':>6} {'budget<5':>9}")
rows=[]
for r in REPOS:
    d=tempfile.mkdtemp()
    if subprocess.run(["git","clone","-q","--depth","1",f"https://github.com/{r}",f"{d}/x"]).returncode: 
        print(f"{r:26} clone-failed"); continue
    # DEFAULT mode (user scanning own code) — harvest+low-confidence gated off
    subprocess.run(["medusa","scan",f"{d}/x","--no-cache","--yes","-o",f"{d}/o"],capture_output=True)
    js=[f for f in glob.glob(f"{d}/o/medusa-scan-*.json") if 'raw-payloads' not in f and 'history' not in f]
    if not js: print(f"{r:26} no-report"); continue
    data=json.load(open(sorted(js,key=os.path.getmtime)[-1]))
    sev=collections.Counter(str(f.get('severity')) for f in data.get('findings',[]))
    c,h,m=sev.get('CRITICAL',0),sev.get('HIGH',0),sev.get('MEDIUM',0)
    medplus=c+h+m
    ok="OK" if medplus<5 else "OVER"
    print(f"{r:26} {c:>5} {h:>5} {m:>5} {medplus:>6} {ok:>9}")
    rows.append((r,c,h,m,medplus))
if rows:
    import statistics
    mp=[x[4] for x in rows]
    print(f"\nrepos: {len(rows)} | median MED+/repo: {statistics.median(mp)} | max: {max(mp)} | within-budget: {sum(1 for x in mp if x<5)}/{len(rows)}")
