# Turns mutant names (one per line, stdin) into anchored cargo-mutants --re
# filters (run A's convention): letters, digits and spaces as is, every other
# character as a one-character class, and [ ] \ ^ - escaped with a backslash.
import sys

sys.stdout.reconfigure(newline="\n")
for line in sys.stdin:
    name = line.rstrip("\r\n")
    if not name:
        continue
    out = []
    for ch in name:
        if (ch.isascii() and ch.isalnum()) or ch == " ":
            out.append(ch)
        elif ch in "[]^-" or ch == chr(92):
            out.append(chr(92) + ch)
        else:
            out.append("[" + ch + "]")
    print("--re=^" + "".join(out) + "$")
