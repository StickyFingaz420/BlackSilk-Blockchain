# Follow-up hand mutants (RT-MUTD): boundary `>=`/`<=` and constants in the
# admission path, one at a time in a copy of the worktree, with the final
# admission oracle; own target directory.
#   python hand4.py <copy-dir> <out-file>
import os, subprocess, sys, time
COPY, OUT = sys.argv[1], sys.argv[2]
S = os.path.dirname(OUT)
tests = [l.strip() for l in open(os.path.join(S, "admission-final.tests"), encoding="utf-8") if l.strip()]
CMD = ["cargo", "test", "--locked", "--profile", "mutants", "-p", "blacksilk-p2p", "--lib",
       "--test", "network", "--", "--exact", "--test-threads=4"] + tests
MUTANTS = [
    ("p2p/src/net/admission.rs", 68, "st.ctx_rejects.len() >= RECENT_REJECTS", "st.ctx_rejects.len() > RECENT_REJECTS", "ctx_reject >= to >"),
    ("p2p/src/net/admission.rs", 354, "r.height + SIGNATURE_BURIAL <= tip", "r.height + SIGNATURE_BURIAL < tip", "burial <= to <"),
    ("p2p/src/net/admission.rs", 18, "const RECENT_REJECTS: usize = 10_000;", "const RECENT_REJECTS: usize = 9_999;", "RECENT_REJECTS 9999"),
    ("p2p/src/net.rs", 172, "TokenBucket::new(2.0, 10.0)", "TokenBucket::new(2.0, 11.0)", "px_global burst 11"),
    ("p2p/src/net.rs", 172, "TokenBucket::new(2.0, 10.0)", "TokenBucket::new(4.0, 10.0)", "px_global rate 4"),
]
env = dict(os.environ)
env.update(CARGO_TARGET_DIR="C:/bszkeval/t-w4-mutd-hand4", CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0")
with open(OUT, "a", encoding="utf-8") as out:
    for path, line, old, new, name in MUTANTS:
        full = os.path.join(COPY, path)
        src = open(full, encoding="utf-8", newline="").read()
        lines = src.split("\n")
        assert old in lines[line - 1], (path, line, lines[line - 1])
        lines[line - 1] = lines[line - 1].replace(old, new)
        open(full, "w", encoding="utf-8", newline="").write("\n".join(lines))
        start = time.time()
        log = os.path.join(S, "hand4-" + name.replace(" ", "_").replace(">", "gt").replace("<", "lt").replace("=", "eq") + ".log")
        try:
            with open(log, "w", encoding="utf-8") as lf:
                r = subprocess.run(CMD, cwd=COPY, env=env, stdout=lf, stderr=subprocess.STDOUT, timeout=900)
            verdict = "CAUGHT" if r.returncode != 0 else "MISSED"
        except subprocess.TimeoutExpired:
            verdict = "TIMEOUT"
        finally:
            open(full, "w", encoding="utf-8", newline="").write(src)
        out.write(f"{verdict}\t{name}\t{path}:{line}\t{time.time() - start:.0f}s\n")
        out.flush()
