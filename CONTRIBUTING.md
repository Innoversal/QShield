# Contributing to QShield

First of all — **thank you** for your interest in contributing to QShield. This project exists to protect the entire internet against quantum computing attacks, and that requires a global community of contributors.

---

## Who We Need

QShield is a large, multi-disciplinary project. We need people with many different skills:

### 🔐 Cryptographers
- Review PQC algorithm implementations for correctness
- Verify constant-time properties of cryptographic code
- Analyze hybrid construction security proofs
- Audit key derivation functions and protocol designs

### ⚙️ Systems Engineers
- Implement TLS 1.3 extensions in C/Rust
- Build OpenSSL provider for PQC algorithms
- Develop WireGuard kernel module modifications
- Optimize performance of PQC operations

### 🌐 Security Researchers
- Threat modeling and attack surface analysis
- Protocol security analysis
- Penetration testing of reference implementations
- CVE research and responsible disclosure

### 🏗️ Infrastructure / DevOps
- Design and build CA infrastructure
- ACME protocol implementation
- High-availability distributed systems
- HSM integration for root key protection

### 📱 Application Developers
- Mobile clients (Android, iOS)
- Desktop applications
- Browser extensions
- Integration libraries for popular languages

### 📝 Technical Writers
- Improve documentation clarity
- Write tutorials and integration guides
- Translate documentation to other languages
- Review whitepaper and technical specs

---

## Getting Started

### 1. Read the Whitepaper
Before contributing code, please read [WHITEPAPER.md](WHITEPAPER.md) to understand the project's goals, threat model, and cryptographic design.

### 2. Find an Issue
Browse [open issues](../../issues) and look for:
- `good first issue` — suitable for new contributors
- `help wanted` — issues where we specifically need contributors
- `cryptography` — needs cryptographic expertise
- `documentation` — writing and documentation tasks

### 3. Discuss Before Building
For significant changes, open an issue or start a [Discussion](../../discussions) before writing code. This avoids wasted effort and ensures alignment with the project direction.

---

## Development Guidelines

### Cryptographic Code Standards

This is a security-critical project. All cryptographic code must:

- **Be constant-time.** Timing side-channels in cryptographic code are critical vulnerabilities. Use established constant-time primitives and have timing analyzed.
- **Use vetted libraries.** Do not implement raw PQC algorithms from scratch for production code. Use liboqs or other audited implementations as the base.
- **Zero sensitive memory.** Private keys and intermediate secrets must be zeroed after use using secure memory clearing functions (not memset, which compilers may optimize away).
- **Avoid custom protocols.** Do not design new cryptographic protocols without community review. Extend existing standards (TLS 1.3, ACME, WireGuard) where possible.

### Code Quality

- All code must be reviewed by at least two maintainers before merging
- Include unit tests for all non-trivial functions
- Include integration tests for protocol-level behavior
- Document all public APIs
- Prefer clarity over cleverness — this code will be security-audited

### Languages

- Core cryptographic library: **C** (with constant-time guarantees) or **Rust**
- TLS and VPN components: **C** or **Rust**
- CA software: **Go** (following Let's Encrypt/Boulder patterns)
- CLI tools: **Go** or **Rust**
- Documentation: **Markdown**

---

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes following the guidelines above
4. Write or update tests as needed
5. Update documentation if your change affects behavior
6. Submit a Pull Request with a clear description of what you changed and why

### PR Description Template

```
## What this PR does
[Clear description of the change]

## Why
[Motivation and context]

## Cryptographic considerations
[If applicable: describe any cryptographic design decisions and why they are safe]

## Testing
[How was this tested?]

## Checklist
- [ ] Code is constant-time where required
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No sensitive data in commit history
```

---

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

If you discover a security vulnerability in QShield, please disclose it responsibly by emailing **security@qshield.io** (to be set up). Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix if you have one

We will respond within 48 hours and coordinate a fix and disclosure timeline with you.

---

## Code of Conduct

QShield is committed to providing a welcoming and inclusive environment for all contributors regardless of background, experience level, gender, nationality, or any other characteristic.

Expected behavior:
- Be respectful and constructive in all communications
- Welcome newcomers and help them get started
- Focus criticism on ideas and code, not people
- Assume good faith

Unacceptable behavior:
- Harassment, insults, or personal attacks
- Dismissing contributions without explanation
- Gatekeeping based on experience level

Violations can be reported to **conduct@qshield.io**.

---

## Recognition

All contributors will be listed in [CONTRIBUTORS.md](CONTRIBUTORS.md). Significant contributions will be acknowledged in release notes.

---

*QShield is built in public, for everyone. Your contribution — no matter how small — helps protect the internet.*
