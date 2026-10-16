# BlackSilk logos: rights notice

**All rights reserved.** The images in this directory are proprietary assets of the
BlackSilk project. They are **not** licensed under `MIT OR Apache-2.0` or under any other
licence of this repository (README, Licence). No permission is granted to use, copy,
modify, redistribute or commercially exploit them without the project's prior written
permission.

**Trademarks.** BlackSilk™ and the BlackSilk logo are used by the project as unregistered
trademarks. No registration has been applied for or granted, as far as this repository
records, so the ® symbol does not apply. Rights in an unregistered mark, where they exist
at all, depend on actual use and on the law of each country. No search for conflicting
marks has been made.

**What this notice is.** It records the project's claim and intent (owner decision,
2026-10-17). It does not by itself establish legal ownership of the images or of any
copyright or trademark in them. It is not legal advice.

## Provenance

No creation record (who made the images, with which tool, from which inputs, under which
terms) is in this repository. The evidence that exists:

- All 14 files were added in one commit, `323009b` (2025-06-11, owner account
  `StickyFingaz420`, message "Refactor code structure for improved readability and
  maintainability"). None has changed since, except as noted below.
- `file_00000000655c61f48af305fcddea7486.png` carried a C2PA content-credentials manifest
  (a `caBX` chunk), stripped without re-encoding on 2026-10-05 (commit `6cf70f8`). The
  manifest, still readable in the version of `323009b`, names ChatGPT, GPT-4o and the
  OpenAI API as the software agent, records the actions "created" and "converted", gives
  the IPTC digital source type `trainedAlgorithmicMedia` (media made by a generative AI
  model), and lists an input image ("image.png") as an ingredient. This indicates the
  image was generated with an AI image tool from an input image of unknown origin; the
  manifest's signature was not independently verified here.
- The other 13 files show the same design (the drape, the network outline and the
  "BlackSilk" lettering) at other sizes and layouts, so they appear to be derived from
  that image. Their only metadata chunk is an ICC colour profile named "ICC Profile",
  which records no tool or author.

In some jurisdictions, works made without sufficient human authorship receive limited or
no copyright protection, and the terms of the AI service used and the rights in the input
image may also matter. The owner should record how the images were created (prompts, input
image and its source, service and its terms at the time, any human editing) to support
the project's claim.

## Per-file status

Status: **confirmed** (evidence of the project's rights exists), **intended** (the owner's
stated intent only), **uncertain** (evidence points to a question that is not resolved).
No file is confirmed.

| File | Size (px) | Added | Metadata | Rights status |
|---|---|---|---|---|
| `file_00000000655c61f48af305fcddea7486.png` | 1024 x 1024 | `323009b`, 2025-06-11 | C2PA manifest (stripped `6cf70f8`): ChatGPT / GPT-4o, AI-generated, input image | intended; uncertain (AI generation, unknown input image) |
| `banner_1600x400.png` | 1600 x 400 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived from the image above) |
| `banner_2560x1440.png` | 2560 x 1440 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `favicon_16x16 (1).png` | 16 x 16 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `favicon_32x32 (2).png` | 32 x 32 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `favicon_48x48.png` | 48 x 48 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `header_800x200.png` | 800 x 200 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `icon_64x64.png` | 64 x 64 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `icon_128x128.png` | 128 x 128 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `icon_256x256.png` | 256 x 256 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `icon_512x512.png` | 512 x 512 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `main_1024x512.png` | 1024 x 512 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `main_1920x1080.png` | 1920 x 1080 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |
| `signature_300x100.png` | 300 x 100 | `323009b`, 2025-06-11 | ICC profile only | intended; uncertain (derived) |

Method: `git log --follow` per file; PNG chunks read with Python's standard library (no
upload, no external tool); the stripped manifest read from `git show 323009b:<file>`.

**Use in the repository:** none. No document, page or build references these files, and
`.dockerignore` keeps them out of the Docker build context. There is no website in this
repository.

Permission requests: open an issue in the project's repository.
