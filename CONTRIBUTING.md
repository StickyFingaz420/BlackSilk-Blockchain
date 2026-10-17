# Contributing to BlackSilk

The engineering rules (consensus discipline, commit trailers, the checks to run before a
push, documentation, pure Rust) are in the README, [Contributing](README.md#contributing).
Security issues never go to a public issue or pull request: [SECURITY.md](SECURITY.md).
This file covers the licence of contributions, the Developer Certificate of Origin and
AI-assisted work. It is project policy, not legal advice.

## Licence of contributions

BlackSilk is licensed `MIT OR Apache-2.0` (README, [Licence](README.md#licence); except
`randomx/`, `third_party/` and `blacksilklogos/`). Unless you state otherwise, any
contribution you intentionally submit for inclusion, as defined in the Apache-2.0 licence,
is dual-licensed `MIT OR Apache-2.0`, without additional terms or conditions (inbound
licence = outbound licence). A change to `randomx/` is contributed under that crate's
`BSD-3-Clause` licence ([randomx/LICENSE](randomx/LICENSE)). The images in
`blacksilklogos/` are not open to contributions under these licences
([blacksilklogos/NOTICE.md](blacksilklogos/NOTICE.md)).

## Developer Certificate of Origin (DCO)

Every commit from a contributor outside the project must carry a sign-off line, in the
last paragraph of the message together with the other trailers:

```
Signed-off-by: Your Name <your.email@example.org>
```

`git commit -s` adds it. By signing off you certify the Developer Certificate of Origin
1.1 for that commit: you wrote it or otherwise have the right to submit it under the
project's licence, and you accept that the sign-off, with your name and e-mail address,
is kept in the public history. The full text is in [docs/DCO.txt](docs/DCO.txt), a
verbatim copy of <https://developercertificate.org/> (its licence permits verbatim
copies). Use a name you are willing to have published; a pseudonym is acceptable if you
can still certify the DCO.

There is no contributor licence agreement (CLA). A sign-off check in CI, required for
merging, is planned before the first external contribution is merged; it is not in
place yet. Until 2026-10-17 every commit in the history was authored by the project
owner's account (some with AI assistance, recorded by `Co-Authored-By:` trailers); none
carries a sign-off.

## AI-assisted contributions

**What the law requires, as far as the project knows:** no rule specific to disclosing
AI assistance in code contributions is known to apply here. The main legal risk of AI
tools is that they can reproduce third-party code verbatim, under a licence that is
incompatible with this project or unknown. Protection of purely AI-generated material may
also be limited in some jurisdictions. The rules below are **project policy**:

- AI tools may assist. A human contributor must review and understand every line, and
  takes responsibility for it as if they had written it.
- The human signs the DCO. An AI tool never adds `Signed-off-by:` and never certifies
  the DCO.
- Disclose AI assistance with a trailer in the last paragraph of the commit message,
  either `Assisted-by: <tool and model>` or the project's existing convention
  `Co-Authored-By: <tool and model> <address>`.
- The trailer marks the commit as AI-assisted. It does not say which lines came from
  the tool.
- No code, data or text may be pasted from a source whose licence is incompatible with
  `MIT OR Apache-2.0` or unknown. Check AI output for verbatim reproduction of
  third-party code (distinctive comments, names or long identical passages; search for
  them). Code taken or ported from a permissively licensed source keeps its notice, is
  named in the commit message and, for shipped code, appears in
  `THIRD-PARTY-NOTICES.md` or the file's header.

A complete commit message ending, for a consensus-path change:

```
Consensus-Change: none: <why this edit does not change consensus>
Assisted-by: <tool and model>
Signed-off-by: Your Name <your.email@example.org>
```
