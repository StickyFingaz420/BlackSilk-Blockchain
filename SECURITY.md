# Security policy

BlackSilk is **experimental software**. Nothing in it has been independently audited,
and no external audit is planned at present (docs/reviews/review-status.md). The
testnet's coins have no value. See AUDIT.md for the internal findings, and
docs/reviews/ for the review material.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it privately through
GitHub's private vulnerability reporting for this repository ("Security" tab, "Report
a vulnerability").

**If the Security tab offers no "Report a vulnerability" button,** private reporting is
not enabled yet (it is a repository setting; checked disabled on 2026-09-27, and its
activation is pending with the maintainer).
- In that case, open a public issue titled only "Security contact request", with **no
  details** of the vulnerability.
- The maintainer will answer with a private channel.
- Never put vulnerability details in a public issue, a pull request or a commit
  message.

Please include:
- the affected component and commit;
- how to reproduce it;
- what an attacker gains (a consensus split, inflation, theft, a privacy leak, a
  denial of service);
- whether you want to be credited.

## What happens next

The response process is docs/testnet-incident-response.md:
- acknowledgement within 2 working days;
- private handling until a fixed release is running;
- publication afterwards, with credit if you wish.

## Scope

Everything in this repository is in scope. These are especially valuable:
- the proof system and its configuration (`zk/`, `zkvm/`, `px-core/`, `px/`,
  `third_party/`);
- consensus rules (`consensus/`, `tx/`, `chain/`);
- anything that reveals private data (docs/reviews/privacy-review.md lists the known
  limitations; those are not new findings).
