# Security policy

BlackSilk is **experimental software**. Nothing in it has been independently audited
yet, and the testnet's coins have no value. See AUDIT.md for the internal findings, and
docs/reviews/ for the review material.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it privately through
GitHub's private vulnerability reporting for this repository ("Security" tab, "Report
a vulnerability").

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
