# W4-MUTAIR scratch helper: in the census copy only, compile out the proving
# tests of the oracle files (they are never run by the census; compiling the
# prover instantiations costs build time per mutant).
import sys, re
names = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith('--')]
for path in sys.argv[2:]:
    s = open(path, encoding='utf-8').read()
    for n in names:
        s = re.sub(r'#\[test\]\n(\s*)fn ' + n + r'\(', r'#[cfg(any())]\n#[test]\n\1fn ' + n + '(', s)
    open(path, 'w', encoding='utf-8', newline='\n').write(s)
