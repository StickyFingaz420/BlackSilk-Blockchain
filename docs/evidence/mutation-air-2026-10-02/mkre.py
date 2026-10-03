# W4-MUTAIR: one anchored --re filter per mutant name (run D's mkre.py
# convention: every character but a letter, digit or space as a one-character
# class, with [ ] \ ^ - escaped).
import sys

for line in open(sys.argv[1], encoding='utf-8'):
    name = line.rstrip('\r\n')
    if not name:
        continue
    out = []
    for ch in name:
        if ch.isalnum() or ch == ' ':
            out.append(ch)
        elif ch in '[]\\^-':
            out.append('[\\' + ch + ']')
        else:
            out.append('[' + ch + ']')
    print('--re')
    print('^' + ''.join(out) + '$')
