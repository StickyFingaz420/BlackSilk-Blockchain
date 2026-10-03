# Run E hand mutants (constant +-1 and others cargo-mutants does not make):
# one at a time in a copy of the committed tree (git archive), each built in
# this script's own target directory, then the oracle; restored after each.
#   python hand.py <spec.tsv> <copy-dir> <target-dir> <out-file> <timeout_s> -- <cargo args...>
# spec.tsv: name <TAB> path <TAB> line <TAB> old <TAB> new
import os, subprocess, sys, time, shutil
spec, COPY, TARGET, OUT, LIMIT = sys.argv[1:6]
assert sys.argv[6] == "--"
CARGO = ["cargo"] + sys.argv[7:]
REPO = "C:/bszkeval/wt-w4-mute"
if not os.path.isdir(COPY):
    os.makedirs(COPY)
    a = subprocess.run(["git", "-C", REPO, "archive", "HEAD"], stdout=subprocess.PIPE, check=True).stdout
    subprocess.run(["tar", "-x", "-f", "-", "-C", COPY], input=a, check=True)
env = dict(os.environ)
env.update(CARGO_TARGET_DIR=TARGET, CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0")
env.pop("BLACKSILK_BUILD_COMMIT", None)
logs = os.path.splitext(OUT)[0] + "-logs"
os.makedirs(logs, exist_ok=True)

def run(cmd, log, limit):
    with open(log, "w", encoding="utf-8") as lf:
        try:
            return subprocess.run(cmd, cwd=COPY, env=env, stdout=lf, stderr=subprocess.STDOUT, timeout=limit).returncode
        except subprocess.TimeoutExpired:
            return 124

def touch(p):
    os.utime(p, None)

build = CARGO[:]
if "--" in build:
    i = build.index("--"); build = build[:i] + ["--no-run"]
else:
    build = build + ["--no-run"]
with open(OUT, "a", encoding="utf-8") as out:
    out.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC; {' '.join(CARGO)}\n")
    rc = run(build, os.path.join(logs, "baseline-build.log"), 3600)
    rc = rc or run(CARGO, os.path.join(logs, "baseline.log"), int(LIMIT))
    out.write(f"baseline {'ok' if rc == 0 else 'FAILED %d' % rc}\n"); out.flush()
    if rc != 0:
        sys.exit(2)
    for k, row in enumerate(l.rstrip("\n") for l in open(spec, encoding="utf-8")):
        if not row or row.startswith("#"):
            continue
        name, path, line, old, new = row.split("\t")
        full = os.path.join(COPY, path)
        src = open(full, encoding="utf-8", newline="").read()
        lines = src.split("\n")
        n = int(line)
        assert old in lines[n - 1], (path, n, lines[n - 1], old)
        lines[n - 1] = lines[n - 1].replace(old, new, 1)
        open(full, "w", encoding="utf-8", newline="").write("\n".join(lines))
        touch(full)
        start = time.time()
        log = os.path.join(logs, f"{k}.log")
        try:
            rc = run(build, log + ".build", 3600)
            if rc != 0:
                verdict = "UNVIABLE"
            else:
                rc = run(CARGO, log, int(LIMIT))
                verdict = "MISSED" if rc == 0 else ("TIMEOUT" if rc == 124 else "CAUGHT")
        finally:
            open(full, "w", encoding="utf-8", newline="").write(src)
            touch(full)
        out.write(f"{verdict}\t{name}\t{path}:{line}\t{old} -> {new}\t{time.time() - start:.0f}s\t{k}.log\n")
        out.flush()
