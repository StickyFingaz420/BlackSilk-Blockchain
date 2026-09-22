# CLAUDE.md — BlackSilk Blockchain

This file guides Claude Code (and other AI agents) working in this repository.
It holds the project audit and Testnet launch plan. Follow it step by step.
Privacy, security, reliability and production readiness come first.

---

## Project Map (quick orientation)

BlackSilk is a privacy-first Rust blockchain monorepo (Cargo workspace, root `Cargo.toml`).

| Path | Role |
|------|------|
| `node/` | Core node: P2P networking (`src/network`), mempool, mining/RandomX verification, HTTP/RPC server, escrow, WASM VM |
| `miner/` | Standalone RandomX CPU miner |
| `primitives/` | Core types: transactions, ring signatures, stealth addresses, ZKP, quantum/PQ primitives |
| `smart-contracts/randomx` | RandomX implementation crate |
| `ml-dsa-44/`, `ml-dsa-44-c/`, `pqsignatures/`, `pqcrypto_native/` | Post-quantum signature implementations and bindings |
| `kats/`, `tests/kat.rs` | NIST Known-Answer Test vectors and tests |
| `wallet/`, `gui-wallet/`, `web-wallet/` | Wallets (CLI, desktop, web) |
| `marketplace/`, `smart-contracts/*` | Marketplace backend and escrow/marketplace contracts |
| `block-explorer/`, `testnet-faucet/` | Explorer and faucet |
| `config/`, `docker/`, `docker-compose*.yml`, `monitoring/`, `i2p/` | Configuration, deployment, monitoring, anonymity-network setup |
| `TESTNET.md`, `TESTNET_LAUNCH.md` | Existing Testnet docs. **Verify them against the code before you trust them.** |

Common commands:

```bash
cargo build --workspace
cargo test --workspace
cargo test --test kat          # ML-DSA-44 NIST KAT tests
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

### Working Rules for Agents

- Do not trust claims in README/TESTNET docs (e.g. "Build Passing" or feature checklists) until the code and tests confirm them.
- Never weaken, skip or delete a test to make a build green. Fix the root cause.
- Consensus-critical changes (block format, PoW, difficulty, signature and tx validation) need tests for both valid and invalid inputs.
- Do not add dependencies unless they are needed and trustworthy. Never add unverified cryptography.
- Record findings, fixes and remaining risks in the **Audit Log** at the bottom of this file, or in a dedicated `docs/audit/` report linked from it.

---

## Professional Project Audit & Testnet Launch Preparation Plan

### 1. Project-Wide Review & Full Ownership

1.1. Review the whole project end to end: architecture, source code, core components, dependencies and overall design.
1.2. Take full technical ownership. Treat the project as one complete system that must be reviewed, refined, tested and prepared for Testnet launch.
1.3. Identify all existing issues, bugs, incomplete implementations, technical debt, security weaknesses and architectural limitations.
1.4. Fix and improve every identified issue using professional software engineering practices.
1.5. Make sure all project components work together seamlessly, consistently and reliably.
1.6. Go beyond surface-level fixes. Examine the project's fundamental principles, design decisions and underlying implementation.

### 2. Privacy-First Architecture & Principles

Privacy is the project's primary objective. It must be the highest priority throughout development.

2.1. Review the project from a privacy-first perspective, starting with its fundamental principles and architectural decisions.
2.2. Examine every component that may affect user privacy, transaction confidentiality, network privacy and data protection.
2.3. Identify potential privacy vulnerabilities, unintended data exposure, metadata leakage and design weaknesses.
2.4. Make sure privacy mechanisms are implemented correctly and consistently across the entire system.
2.5. Verify that privacy features deliver their intended guarantees and do not rely on unverified assumptions.
2.6. Strengthen the privacy architecture wherever needed while keeping the project's core functionality compatible.

### 3. Comprehensive Security Audit

3.1. Audit the security of every project component, including the cryptographic, networking, consensus, node and mining systems.
3.2. Review all cryptographic implementations and security-critical code for correctness, reliability and potential vulnerabilities.
3.3. Verify that all cryptographic signatures and security mechanisms are implemented correctly and work as intended.
3.4. Check signature generation, verification, key handling and validation logic wherever they apply.
3.5. Identify and resolve vulnerabilities, implementation flaws, insecure configurations and potential attack vectors.
3.6. Make sure security mechanisms are actually integrated throughout the system, not merely present in the code.
3.7. Verify security-critical functionality with appropriate testing, code analysis and validation methods.
3.8. Document any unresolved security risks or limitations. Do not assume an untested mechanism is secure.

### 4. Proof-of-Work & RandomX Verification

4.1. Verify that the project's Proof-of-Work mining algorithm is RandomX.
4.2. Review the RandomX implementation and its integration throughout the project.
4.3. Confirm that the correct algorithm configuration is used and that no unintended or inconsistent mining algorithms are present.
4.4. Audit the implementation of mining, hashing, difficulty adjustment, block validation and Proof-of-Work verification.
4.5. Make sure the node validates Proof-of-Work correctly and rejects invalid or improperly constructed blocks.
4.6. Verify that the mining process is compatible with the project's consensus rules.
4.7. Identify and resolve any issues affecting the correctness, security, performance or reliability of the RandomX integration.
4.8. Use appropriate tests to confirm that the implementation behaves as expected under valid and invalid conditions.

### 5. Node Architecture & Implementation Review

5.1. Review the node implementation and architecture completely.
5.2. Make sure the node is professionally designed, secure, reliable, maintainable and suitable for Testnet deployment.
5.3. Review the following node components:
   - Network communication and peer-to-peer functionality.
   - Block propagation and validation.
   - Blockchain synchronization.
   - Consensus implementation.
   - Transaction processing and validation.
   - Chain selection and reorganization handling.
   - Mempool management.
   - Error handling and recovery.
   - Resource management and performance.
   - Security against invalid or malicious network activity.

5.4. Verify that the node follows the project's consensus rules consistently.
5.5. Identify and fix synchronization issues, validation weaknesses, networking problems and reliability concerns.
5.6. Make sure the node can operate correctly in realistic Testnet conditions.
5.7. Improve the node's maintainability, observability and operational reliability where needed.

### 6. Mining System Review & Optimization

6.1. Review the entire mining implementation thoroughly.
6.2. Verify that mining is correctly integrated with the RandomX Proof-of-Work algorithm.
6.3. Review the following mining components:
   - Mining algorithm integration.
   - Block template generation.
   - Nonce handling.
   - Hash calculation.
   - Difficulty and target verification.
   - Block submission.
   - Miner-to-node communication.
   - Mining error handling.
   - Performance and resource utilization.

6.4. Make sure miners produce valid blocks that comply with the project's consensus rules.
6.5. Verify that the node correctly validates and processes mined blocks.
6.6. Identify and resolve bugs, inefficiencies, security vulnerabilities and integration issues.
6.7. Make sure the mining system is stable, reliable and ready for Testnet testing.

### 7. Code Quality, Architecture & Professional Standards

7.1. Review the codebase for quality, consistency, maintainability and adherence to professional engineering practices.
7.2. Identify unnecessary complexity, duplicated logic, poor abstractions and outdated implementations.
7.3. Refactor code where needed without compromising security, privacy or compatibility.
7.4. Make sure project components have clear responsibilities and appropriate separation of concerns.
7.5. Review dependencies, configurations, build processes and environment-specific settings.
7.6. Make sure error handling, logging and diagnostics are appropriate for development and Testnet operations.
7.7. Avoid unnecessary dependencies, insecure shortcuts and unverified third-party implementations.

### 8. Comprehensive Testing & Validation

8.1. Set up and run a structured testing strategy for the entire project.
8.2. Review existing tests and identify missing coverage in critical components.
8.3. Add or improve tests where needed, including:
   - Unit testing.
   - Integration testing.
   - End-to-end testing.
   - Consensus and block validation testing.
   - Cryptographic signature verification testing.
   - RandomX Proof-of-Work testing.
   - Node synchronization testing.
   - Mining functionality testing.
   - Network and peer-to-peer testing.
   - Error handling and recovery testing.
   - Security and adversarial testing.

8.4. Verify that all critical functionality works correctly under both valid and invalid conditions.
8.5. Run the appropriate build, test and validation processes after every change.
8.6. Investigate and resolve test failures. Never ignore or bypass them.
8.7. Make sure improvements do not introduce regressions or break existing functionality.

### 9. Testnet Readiness & Launch Preparation

9.1. Evaluate the project's overall readiness for the Testnet phase.
9.2. Verify that all essential components are correctly implemented, integrated and tested.
9.3. Review Testnet-specific configurations, including:
   - Network parameters.
   - Genesis block and initial chain configuration.
   - Chain ID and network identification.
   - Consensus and difficulty settings.
   - Node configuration.
   - Mining configuration.
   - Peer-to-peer networking.
   - Logging and monitoring.
   - Error handling and recovery procedures.

9.4. Identify any missing components or unresolved issues that could block a successful Testnet launch.
9.5. Make sure the project can be deployed and operated reliably in a controlled Testnet environment.
9.6. Verify that critical security and privacy guarantees are backed by appropriate testing and evidence.
9.7. Prepare the project for launch only after the necessary validation is complete and critical blockers are addressed.

### 10. Documentation & Technical Reporting

10.1. Keep clear and accurate documentation of all significant changes made during the review.
10.2. Document each identified issue, its root cause and the implemented solution.
10.3. Record testing procedures, results and any remaining limitations.
10.4. Clearly identify unresolved security, privacy, consensus or reliability risks.
10.5. Make sure project documentation reflects the actual implementation and does not claim features or guarantees that have not been verified.
10.6. Provide a structured summary of the project's readiness, including any tasks that remain before Testnet launch.

### 11. Final Objective & Execution Guidelines

#### Primary Mission

Take full technical ownership of the project and turn it into a professional, secure, privacy-focused, stable and Testnet-ready system.

Follow these principles throughout the entire process:

1. **Privacy First:** Treat privacy as the core objective of the project.
2. **Security by Design:** Verify security mechanisms through rigorous review and testing.
3. **Correctness Over Assumptions:** Validate implementations instead of assuming they work.
4. **Professional Engineering:** Apply maintainable, scalable and reliable development practices.
5. **Comprehensive Review:** Examine the entire project, not only the visible bugs.
6. **Evidence-Based Validation:** Back every readiness claim with actual testing and verification.
7. **No Superficial Fixes:** Address root causes and architectural weaknesses where needed.
8. **Testnet Readiness:** Make sure the project is properly prepared for a controlled and reliable Testnet launch.

#### Expected Final Outcome

By the end of this process, the project should be:

- Fully reviewed and audited across all major components.
- Privacy-focused and designed with appropriate privacy protections.
- Backed by correctly implemented and tested security mechanisms.
- Using RandomX for Proof-of-Work and validating it correctly.
- Equipped with a professional and reliable node implementation.
- Equipped with a stable and properly integrated mining system.
- Tested across critical functionality and integration points.
- Documented, including identified risks, limitations and remaining tasks.
- Prepared for Testnet launch, subject to completing all required validation and security checks.

Execute this plan systematically and prioritize critical issues. **Do not declare the project Testnet-ready until the necessary reviews, tests and validations are complete.**

---

## Audit Log

Record progress per plan section. For each entry, note the date, the section, the finding or change, the evidence (test or command output), and its status.

| Date | Section | Finding / Change | Evidence | Status |
|------|---------|------------------|----------|--------|
| 2026-09-22 | — | Audit plan added to `CLAUDE.md` | — | Plan in place; audit not yet started |

### Testnet Readiness Status

**NOT READY.** The audit has not been performed yet. Update this status only when the evidence recorded above supports the change.
