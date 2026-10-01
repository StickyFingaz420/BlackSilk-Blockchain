# Per mutant log of a cargo-mutants run: the mutant and the tests that failed.
import glob, os, re, sys
for d in sys.argv[1:]:
    print("#####", d)
    for f in sorted(glob.glob(os.path.join(d, "mutants.out", "log", "*.log"))):
        with open(f, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        m = re.search(r"^\*\*\* (.*)$", text, re.M)
        fails = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", text, re.M)))
        extra = ""
        if not fails:
            e = re.search(r"exit code: \d+|panicked at [^\n]*", text)
            extra = e.group(0) if e else "(none)"
        ovf = " [overflow]" if "with overflow" in text else ""
        print((m.group(1) if m else f)[:95], "|", " ".join(fails)[:160] or extra, ovf)
