# Boundary pass of mutation run D: the mutants cargo-mutants 27.1.0 never
# generates, `>=` -> `>` and `<=` -> `<`, for every such operator in the run's
# scope. Each is applied to a copy of the worktree (one at a time), the
# oracle runs, and the original file is restored.
#   python boundary.py <copy-dir> <out-file>
import os, subprocess, sys, time

COPY, OUT = sys.argv[1], sys.argv[2]
ZK = ["cargo", "test", "--locked", "--profile", "mutants", "-p", "blacksilk-zk",
      "--lib", "--test", "decode_bounds", "--test", "rt_pxdos_differential"]
CONSENSUS = ["cargo", "test", "--locked", "--profile", "mutants", "-p", "blacksilk-consensus"]
# (file, line, column of the operator's first character, operator, oracle, timeout s)
MUTANTS = [
    ("zk/src/bounds.rs", 139, 24, "<=", ZK, 900),
    ("consensus/src/pow.rs", 28, 15, "<=", CONSENSUS, 1500),
    ("consensus/src/pow.rs", 291, 27, "<=", CONSENSUS, 1500),
    ("consensus/src/pow.rs", 417, 51, "<=", CONSENSUS, 1500),
    ("consensus/src/pow.rs", 418, 58, "<=", CONSENSUS, 1500),
]
REPL = {">=": ">", "<=": "<"}

env = dict(os.environ)
env.update(CARGO_TARGET_DIR="C:/bszkeval/t-w4-mutd-bnd", CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0")
with open(OUT, "a", encoding="utf-8") as out:
    for path, line, col, op, cmd, limit in MUTANTS:
        full = os.path.join(COPY, path)
        with open(full, encoding="utf-8", newline="") as f:
            src = f.read()
        lines = src.split("\n")
        text = lines[line - 1]
        assert text[col - 1:col + 1] == op, (path, line, col, text)
        lines[line - 1] = text[:col - 1] + REPL[op] + text[col + 1:]
        name = f"{path}:{line}:{col}: replace {op} with {REPL[op]}"
        with open(full, "w", encoding="utf-8", newline="") as f:
            f.write("\n".join(lines))
        start = time.time()
        log = os.path.join(os.path.dirname(OUT), "boundary-" + path.replace("/", "__") + f"_{line}.log")
        try:
            with open(log, "w", encoding="utf-8") as lf:
                lf.write(f"*** {name}\n{lines[line - 1].strip()}\n")
                lf.flush()
                r = subprocess.run(cmd, cwd=COPY, env=env, stdout=lf, stderr=subprocess.STDOUT, timeout=limit)
            verdict = "CAUGHT" if r.returncode != 0 else "MISSED"
        except subprocess.TimeoutExpired:
            verdict = "TIMEOUT"
        finally:
            with open(full, "w", encoding="utf-8", newline="") as f:
                f.write(src)
        out.write(f"{verdict}\t{name}\t{time.time() - start:.0f}s\n")
        out.flush()
