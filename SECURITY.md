# Security Policy

## Reporting Security Vulnerabilities

The BlackSilk team takes security seriously. We appreciate your efforts to responsibly disclose any security vulnerabilities you find.

### Scope

This security policy applies to the following BlackSilk components:

**In Scope:**
- BlackSilk Node (core blockchain implementation)
- BlackSilk Miner (RandomX mining implementation) 
- BlackSilk Wallet (CLI wallet and privacy features)
- BlackSilk Marketplace (backend and frontend)
- BlackSilk Primitives (cryptographic libraries)
- Official documentation and configuration examples

**Out of Scope:**
- Third-party dependencies (please report to the respective maintainers)
- Social engineering attacks
- Physical attacks on infrastructure
- Attacks requiring social engineering or physical access to devices

### How to Report a Vulnerability

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities through one of these channels:

#### 1. Encrypted Email (Preferred)

Send an email to: **security@blacksilk.io**

Use our PGP key to encrypt sensitive information:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP PUBLIC KEY WILL BE ADDED HERE]
-----END PGP PUBLIC KEY BLOCK-----
```

#### 2. GitHub Security Advisories

Use GitHub's private vulnerability reporting feature:
1. Go to the Security tab in this repository
2. Click "Report a vulnerability"
3. Fill out the private advisory form

#### 3. Responsible Disclosure Platform

Report through our HackerOne program (coming soon):
- **Program URL**: https://hackerone.com/blacksilk (when available)

### What to Include in Your Report

To help us understand and reproduce the issue, please include:

1. **Description**: A clear description of the vulnerability
2. **Impact**: The potential impact and severity
3. **Reproduction Steps**: Detailed steps to reproduce the issue
4. **Proof of Concept**: Code, screenshots, or other evidence
5. **Environment**: Version, OS, network (testnet/mainnet)
6. **Suggested Fix**: If you have ideas for remediation

### Example Report Format

```
Subject: [SECURITY] Vulnerability in BlackSilk Node RPC

Component: BlackSilk Node
Severity: High
Affected Versions: v1.0.0 and earlier

Description:
[Detailed description of the vulnerability]

Impact:
[What an attacker could achieve]

Reproduction Steps:
1. Start BlackSilk node with default configuration
2. Send malformed RPC request to /api/endpoint
3. Observe [specific behavior]

Proof of Concept:
[Code snippet or curl command]

Environment:
- BlackSilk version: v1.0.0
- OS: Ubuntu 22.04
- Network: Testnet

Suggested Fix:
[Your suggestions for fixing the issue]
```

### Response Timeline

We will acknowledge receipt of your vulnerability report within **24 hours**.

Our security response timeline:

- **24 hours**: Initial acknowledgment
- **72 hours**: Initial assessment and triage
- **7 days**: Regular updates on investigation progress
- **30 days**: Target resolution for most vulnerabilities
- **90 days**: Maximum time before public disclosure (coordinated)

### Severity Classification

We use the following severity levels:

#### Critical
- Remote code execution
- Privilege escalation
- Consensus-breaking vulnerabilities
- Private key extraction
- Unlimited token creation

#### High  
- Local code execution
- Cross-site scripting (XSS) with session hijacking
- SQL injection with data access
- Transaction malleability
- Ring signature bypass

#### Medium
- Information disclosure
- Denial of service
- Cross-site request forgery (CSRF)
- Privacy leaks
- Fee manipulation

#### Low
- Non-security configuration issues
- Information leakage with minimal impact
- Minor privacy concerns

### Bug Bounty Program

We operate a bug bounty program to reward security researchers:

#### Reward Structure

| Severity | Testnet | Mainnet |
|----------|---------|---------|
| **Critical** | $1,000 - $5,000 | $5,000 - $25,000 |
| **High** | $500 - $2,000 | $2,000 - $10,000 |
| **Medium** | $200 - $1,000 | $1,000 - $5,000 |
| **Low** | $50 - $500 | $250 - $1,500 |

#### Bonus Rewards

- **First Reporter**: +50% bonus for being first to report a vulnerability
- **High Quality Report**: +25% bonus for exceptional documentation
- **Fix Included**: +25% bonus for providing a working fix
- **Multiple Vulnerabilities**: +10% per additional valid vulnerability in the same report

#### Eligibility

To be eligible for rewards:

- Vulnerability must be in scope
- Must follow responsible disclosure
- Cannot be a duplicate of a previously reported issue
- Must not violate any laws or breach any agreements
- Must not cause harm to BlackSilk users or infrastructure

### Coordinated Disclosure

We believe in coordinated disclosure to protect our users:

1. **Private Discussion**: We'll work with you privately to understand and fix the issue
2. **Fix Development**: We'll develop and test a fix
3. **Release Planning**: We'll coordinate the timing of the fix release
4. **Public Disclosure**: After the fix is deployed, we'll publicly acknowledge your contribution (if desired)

### Safe Harbor

We provide the following safe harbor for security research:

- We will not pursue legal action against you for security research conducted in good faith
- We will not report you to law enforcement for good faith security research
- We consider good faith security research to be:
  - Testing only on testnet when possible
  - Not accessing or modifying data belonging to others
  - Not performing attacks that could harm availability or integrity
  - Not using social engineering or physical attacks
  - Reporting vulnerabilities promptly and confidentially

### Security Measures

BlackSilk implements several security measures:

#### Code Security
- Static analysis tools (Clippy, cargo-audit)
- Dependency vulnerability scanning
- Regular security reviews
- Unit and integration testing

#### Infrastructure Security
- Secure development practices
- Protected build pipeline
- Signed releases
- Infrastructure monitoring

#### Operational Security
- Incident response procedures
- Security awareness training
- Regular security assessments
- Backup and recovery procedures

### Past Security Issues

We maintain transparency about past security issues:

| Date | Severity | Component | Description | Status |
|------|----------|-----------|-------------|--------|
| TBD | TBD | TBD | TBD | TBD |

*No security issues have been reported to date.*

### Security Contact Information

- **Primary Contact**: security@blacksilk.io
- **Backup Contact**: admin@blacksilk.io
- **Response Time**: 24 hours maximum
- **PGP Key**: Available at https://keybase.io/blacksilk

### Additional Resources

- **Security Documentation**: https://docs.blacksilk.io/security
- **Developer Security Guide**: https://docs.blacksilk.io/dev/security
- **Security Best Practices**: https://docs.blacksilk.io/best-practices
- **Incident Response**: https://docs.blacksilk.io/incident-response

---

## Acknowledgments

We want to thank the following individuals for their responsible disclosure of security vulnerabilities:

*No security researchers have been acknowledged yet.*

---

**Last Updated**: January 2025

For questions about this security policy, please contact security@blacksilk.io.
