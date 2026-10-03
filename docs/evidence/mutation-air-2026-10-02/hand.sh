#!/usr/bin/env bash
# W4-MUTAIR hand mutants (constants ±1): applies each line of a spec file
# (id|file|line|from|to; `from` must occur exactly once on that line) to the
# census copy `src`, one at a time, runs the aggregated oracle, restores the
# file. Own target dir. Output: $2/outcomes.txt and $2/<id>.log.
set -u
spec="$(realpath "$1")"; out="$2"; mkdir -p "$out"
cd "$(dirname "$0")/src-hand"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=C:/bszkeval/t-w4-mutair-hand
cfg=profile.mutants.package.blacksilk-zkvm.opt-level=1
while IFS='|' read -r id file line from to; do
  [ -n "$id" ] || continue
  cp "$file" "$file.orig"
  F="$from" T="$to" L="$line" perl -e '
    my ($f, $t, $l) = @ENV{qw(F T L)}; my $n = 0; my @lines = <STDIN>;
    my $c = () = $lines[$l - 1] =~ /\Q$f\E/g;
    die "match count $c at line $l\n" unless $c == 1;
    $lines[$l - 1] =~ s/\Q$f\E/$t/; print @lines;' < "$file.orig" > "$file" || { echo "badspec $id" | tee -a "$out/outcomes.txt"; mv "$file.orig" "$file"; continue; }
  touch "$file"
  { echo "*** $id $file:$line: $from -> $to"; diff "$file.orig" "$file"; } > "$out/$id.log"
  rc=0
  timeout 2400 cargo test --locked --profile mutants --config "$cfg" -p blacksilk-zkvm --test air_oracle --no-run >> "$out/$id.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then verdict=unviable
  else
    powershell -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w C:/bszkeval/wt-w4-mutair/tools/run-with-timeout.ps1)"       -TimeoutSec 900 -WorkDir "$(cygpath -w "$PWD")" -Log "$(cygpath -w "$out/$id.test")" -Exe cargo       -ArgLine "test --locked --profile mutants --config $cfg -p blacksilk-zkvm --test air_oracle -- --test-threads=2" || rc=$?
    cat "$out/$id.test" "$out/$id.test.stderr" >> "$out/$id.log" 2>/dev/null; rm -f "$out/$id.test" "$out/$id.test.stderr"
    if [ "$rc" -eq 0 ]; then verdict=missed; elif [ "$rc" -eq 124 ]; then verdict=timeout; else verdict=caught; fi
  fi
  mv "$file.orig" "$file"; touch "$file"
  echo "$verdict $id $file:$line $from -> $to" | tee -a "$out/outcomes.txt"
done < "$spec"
