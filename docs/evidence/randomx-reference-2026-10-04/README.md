# B4: BlackSilk salted RandomX known answers, reproduced with the reference implementation

Date: 2026-10-04. Repo state checked: `rebuild/core` HEAD `de9e2ca`. Everything below was built
off-tree under `C:\bszkeval\rx-ref\`. The reference build itself was never added to the BlackSilk repository; only these results, the driver source (as text) and the build script are kept here as evidence.

## Reference used

- Source: https://github.com/tevador/RandomX, tag `v1.2.3`, commit `12f2c2ffe2108d6cf54c391fee33c8bc3646cdab`.
  `randomx/README.md` cites v1.2.3 as the source of the vectors.
- `src-stock/`: the tag with no changes. This is the control.
- `src-bs/`: the same tag with exactly one change, in `src/configuration.h`:
  ```
  -#define RANDOMX_ARGON_SALT         "RandomX\x03"
  +#define RANDOMX_ARGON_SALT         "BlackSilk/RandomX/v1"
  ```
- Toolchain: MSVC 14.44.35207 from VS 2022 Community, and the CMake bundled with VS
  (`Common7\IDE\CommonExtensions\Microsoft\CMake`). Nothing was installed.

## Driver

`kat.cpp` is about 90 lines and uses only the public API: `randomx_alloc_cache`, `randomx_init_cache`,
`randomx_create_vm(flags, cache, nullptr)` (light mode, no dataset), `randomx_vm_set_cache` and
`randomx_calculate_hash`. The vector bytes are copied from:
- `randomx/src/self_test.rs`: the keys and inputs of `VECTORS` (1a..1f) and `BLACKSILK_VECTORS` (bs-1a..bs-1f).
- `consensus/tests/golden.rs`: the `randomx_known_answer_on_a_mining_blob` key is the regtest genesis id
  `3dbdba2aca8842cd3e02c7d8c72078f77ff132cc3c84a7f8b87891d0cc106141` (pinned in `genesis_ids_golden`).
  Its input is the sample header's `pow_blob(0x00DEB06E)`, where 0x00DEB06E is the regtest network id from
  `params.rs`. That blob is 47 bytes and is pinned in `header_bytes_and_id_golden`:
  `4253696c6b2f31 c5f088aff29464163b4516459f5e38ce6e9c5588247dae5f0cab3ca8fc8c2b13 efbeadde00000000`.

The driver runs in three modes:
- `interp`: flags 0x0, i.e. `RANDOMX_FLAG_DEFAULT`, which is the interpreter with software AES.
- `jit`: flags 0x8, i.e. `RANDOMX_FLAG_JIT`.
- `auto`: flags 0x6a, i.e. `randomx_get_flags()`, which on this CPU is JIT, hard AES and the AVX2/SSSE3 Argon variants.

## Reproduce

```
git clone https://github.com/tevador/RandomX C:/bszkeval/rx-ref/src-stock && git -C C:/bszkeval/rx-ref/src-stock checkout v1.2.3
git clone C:/bszkeval/rx-ref/src-stock C:/bszkeval/rx-ref/src-bs && git -C C:/bszkeval/rx-ref/src-bs checkout v1.2.3
# edit src-bs/src/configuration.h line 41 as in the diff above
cmd /c C:\bszkeval\rx-ref\build.bat          # cmake (VS 17 2022, x64, Release, /m:2), then cl kat.cpp per variant
kat-stock.exe interp|jit|auto ; kat-bs.exe interp|jit|auto
```
Raw output is in `kat-output.txt` and the build log is in `build.log`.

## Results

All three modes printed identical outputs for each variant.

### Control: stock build, Monero salt

| vector | expected (self_test.rs `VECTORS`) | reference output | |
|---|---|---|---|
| 1a | 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f | 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f | MATCH |
| 1b | 300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969 | same | MATCH |
| 1c | c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8 | same | MATCH |
| 1d | e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc | same | MATCH |
| 1e | c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1 | same | MATCH |
| 1f | 78af2a1864c42abce36d2e8983e13df99b2af0ce1362999af09fab004d4435a8 | same | MATCH |
| blob (stock salt) | n/a | 35f3e02e45142956eb64e2f004a17f030e41b61d3cf2f85c7ac8e46ad29e58da | differs from 410e…, as expected |

The stock reference suite `build-stock\Release\randomx-tests.exe` also passed all 95 tests
(output in `randomx-tests-stock.txt`).

### BlackSilk salt build (`"BlackSilk/RandomX/v1"`)

| vector | expected (repo) | reference output | |
|---|---|---|---|
| bs-1a | 424838440b398cd20d703905167a6d07b19816b0ab246b678218649fa7d70802 | 424838440b398cd20d703905167a6d07b19816b0ab246b678218649fa7d70802 | MATCH |
| bs-1b | 7d742273815a73a2fea8b7e0102bf8b47d6b7cd2657a3cd7a7d2dd9f4e798d8f | 7d742273815a73a2fea8b7e0102bf8b47d6b7cd2657a3cd7a7d2dd9f4e798d8f | MATCH |
| bs-1c | 182e687dcbd7d60daecef46c8b7a3369fa0b0e5517d21b57a31b1bf7ff9c5bb6 | 182e687dcbd7d60daecef46c8b7a3369fa0b0e5517d21b57a31b1bf7ff9c5bb6 | MATCH |
| bs-1d | 7c5f9da95f68936abddc00535549716ccb5c1c5965fe31fc7cd8d047950bcede | 7c5f9da95f68936abddc00535549716ccb5c1c5965fe31fc7cd8d047950bcede | MATCH |
| bs-1e | a4687b72af500c1e764655b42db9580ee0b72a6c06b8020d97597ec037b2c1bf | a4687b72af500c1e764655b42db9580ee0b72a6c06b8020d97597ec037b2c1bf | MATCH |
| bs-1f | 2d2e59cff0b64955878021d9c35b3300f93980434522b15e8cde421210ca35ae | 2d2e59cff0b64955878021d9c35b3300f93980434522b15e8cde421210ca35ae | MATCH |
| golden.rs mining blob | 410e353c0ecbcea5389d97931ed60ce2a4382c30619de617728a4d858e2d97c1 | 410e353c0ecbcea5389d97931ed60ce2a4382c30619de617728a4d858e2d97c1 | MATCH |

Note on `build-bs\Release\randomx-tests.exe`: upstream gates most salt-dependent tests on the stock salt,
and those are reported as SKIPPED. The "Preserve rounding mode" test is not gated: it asserts the Monero
1b hash, so it aborts at tests.cpp:1108 in the salted build. This is an upstream test-gating gap and is
expected. It is not a mismatch, and it is consistent with bs-1b above.

## Conclusion

An unmodified tevador/RandomX v1.2.3 reproduces all seven of BlackSilk's salted known answers when the
only change is the documented salt. That is bs-1a..bs-1f plus the consensus mining-blob KAT. The interpreter,
the JIT and the auto-detected hard-AES/AVX2 paths all agree, and the stock build reproduces the official
1a..1f. This is independent evidence that the pure-Rust `blacksilk-randomx` crate computes RandomX with
`ARGON_SALT = "BlackSilk/RandomX/v1"` and no other deviation. The evidence covers light mode only; full-mode
dataset hashing equals light-mode hashing by construction in the reference, but this run did not exercise it.

## xmrig (step 5, assessment only, not attempted)

Adding `rx/blacksilk` to xmrig looks feasible at the hashing level. xmrig already keeps one
`RandomX_ConfigurationBase` per algorithm with its own `ArgonSalt` (for example Wownero's `"RandomWOW\x01"`),
so a new config with `ArgonSalt = "BlackSilk/RandomX/v1"`, plus an algorithm id and name in
`Algorithm.h/.cpp` and `RxAlgo`, is a change of about five files. The heavier work is integration:
- xmrig's CryptoNote job model assumes a 4-byte nonce at blob offset 39. BlackSilk's 47-byte blob has an
  8-byte little-endian nonce at offset 39, so xmrig would only search the low 32 bits unless it is extended.
- Its daemon mode speaks Monero's `get_block_template`/`submit_block` RPC, so a stratum or pool bridge for
  BlackSilk's node would be needed.
This is not tested now. It is a separate build of a large C++ codebase with an integration bridge.

## Driver source (kat.cpp, kept here as text: the repository has no C/C++ sources)

```cpp
// Off-tree known-answer driver for the tevador/RandomX reference (light mode).
// Usage: kat <interp|jit|auto>
//   interp: RANDOMX_FLAG_DEFAULT (interpreter, software AES)
//   jit:    RANDOMX_FLAG_JIT
//   auto:   randomx_get_flags() (JIT + hard AES etc. as detected)
// Prints: name key_hex input_hex hash_hex
#include "randomx.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static std::vector<unsigned char> unhex(const char* s) {
	std::vector<unsigned char> v;
	size_t n = strlen(s);
	for (size_t i = 0; i + 1 < n; i += 2) {
		unsigned int b;
		sscanf(s + i, "%2x", &b);
		v.push_back((unsigned char)b);
	}
	return v;
}
static std::vector<unsigned char> str(const char* s) {
	return std::vector<unsigned char>(s, s + strlen(s));
}
static std::string hex(const unsigned char* p, size_t n) {
	static const char* d = "0123456789abcdef";
	std::string s;
	for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
	return s;
}

struct V { const char* name; std::vector<unsigned char> key, input; };

int main(int argc, char** argv) {
	std::string mode = argc > 1 ? argv[1] : "interp";
	randomx_flags flags = RANDOMX_FLAG_DEFAULT;
	if (mode == "jit") flags = RANDOMX_FLAG_JIT;
	else if (mode == "auto") flags = randomx_get_flags();
	printf("# mode=%s flags=0x%x\n", mode.c_str(), (unsigned)flags);

	const char* lorem = "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua";
	std::vector<V> vs = {
		{"1a", str("test key 000"), str("This is a test")},
		{"1b", str("test key 000"), str("Lorem ipsum dolor sit amet")},
		{"1c", str("test key 000"), str(lorem)},
		{"1d", str("test key 001"), str(lorem)},
		{"1e", str("test key 001"), unhex("0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416")},
		{"1f", unhex("7797373ea4633194640bf8d8c3b66724d6aa7bd2dc20e009df2f8f1710abe8"), unhex("1010e1eaf8cf067b37b5f0ee031ab23ed1755e090a3af4415830145853e2be3e1f6821fed84dae58d00e00da5214d6c1f2d0622e0abd51f9373d04e0b0f8e6d6514d90689721c4aac5a9bb0d")},
		// consensus/tests/golden.rs randomx_known_answer_on_a_mining_blob:
		// key = regtest genesis id, input = sample header pow_blob(0x00DEB06E) (47 bytes)
		{"blob", unhex("3dbdba2aca8842cd3e02c7d8c72078f77ff132cc3c84a7f8b87891d0cc106141"),
		         unhex("4253696c6b2f31" "c5f088aff29464163b4516459f5e38ce6e9c5588247dae5f0cab3ca8fc8c2b13" "efbeadde00000000")},
	};

	std::vector<unsigned char> lastKey;
	randomx_cache* cache = randomx_alloc_cache(flags);
	if (!cache) { fprintf(stderr, "alloc_cache failed\n"); return 1; }
	randomx_vm* vm = nullptr;
	for (auto& v : vs) {
		if (v.key != lastKey) {
			randomx_init_cache(cache, v.key.data(), v.key.size());
			lastKey = v.key;
			if (vm) randomx_vm_set_cache(vm, cache);
		}
		if (!vm) {
			vm = randomx_create_vm(flags, cache, nullptr);
			if (!vm) { fprintf(stderr, "create_vm failed\n"); return 1; }
		}
		unsigned char h[RANDOMX_HASH_SIZE];
		randomx_calculate_hash(vm, v.input.data(), v.input.size(), h);
		printf("%s key=%s input_len=%zu hash=%s\n", v.name, hex(v.key.data(), v.key.size()).c_str(),
		       v.input.size(), hex(h, sizeof h).c_str());
	}
	randomx_destroy_vm(vm);
	randomx_release_cache(cache);
	return 0;
}

```

## Build script (build.bat)

```bat
@echo off
rem Off-tree build of tevador/RandomX v1.2.3: stock and BlackSilk-salted, plus kat.exe driver.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set CMAKE="C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
cd /d C:\bszkeval\rx-ref
for %%V in (stock bs) do (
  %CMAKE% -S src-%%V -B build-%%V -G "Visual Studio 17 2022" -A x64 || exit /b 1
  %CMAKE% --build build-%%V --config Release -- /m:2 /v:minimal || exit /b 1
  cl /nologo /O2 /EHsc /MD /Isrc-%%V\src kat.cpp /Fokat-%%V.obj /Fekat-%%V.exe build-%%V\Release\randomx.lib advapi32.lib || exit /b 1
)
echo BUILD OK

```
