# QShield Roadmap

This document outlines the development plan for QShield. The roadmap is community-driven and will evolve based on contributor availability and community feedback.

---

## Phase 1 — QShield TLS (Months 1–4)
**Goal:** A working, audited, hybrid quantum-safe TLS 1.3 implementation.

- [ ] Implement CRYSTALS-Kyber 768 (wrapping liboqs)
- [ ] Implement CRYSTALS-Dilithium 3 (wrapping liboqs)
- [ ] Implement hybrid X25519Kyber768 key share for TLS 1.3 ClientHello
- [ ] Build OpenSSL 3.x provider for PQC algorithms
- [ ] Nginx integration module
- [ ] Apache integration module
- [ ] Test suite with interoperability tests
- [ ] Performance benchmarks
- [ ] First independent security review

**Deliverable:** `qshield-tls` library + Nginx/Apache modules, usable by any server operator.

---

## Phase 2 — QShield CA (Months 5–9)
**Goal:** A free, automated Certificate Authority issuing quantum-safe certificates.

- [ ] Fork and extend Boulder (Let's Encrypt CA software)
- [ ] Add Dilithium3 certificate signing capability
- [ ] Hybrid certificate format (RSA + Dilithium in same certificate)
- [ ] ACME v2 protocol compliance
- [ ] Certbot plugin
- [ ] Certificate Transparency log integration
- [ ] Staging environment launch
- [ ] Public beta

**Deliverable:** Free quantum-safe certificates for any domain, issued automatically.

---

## Phase 3 — QShield VPN (Months 10–14)
**Goal:** A WireGuard-compatible VPN with quantum-safe key exchange.

- [ ] Fork WireGuard userspace implementation
- [ ] Replace Curve25519 ECDH with hybrid X25519+Kyber768
- [ ] Linux kernel module (or eBPF implementation)
- [ ] `wg`-compatible CLI tools
- [ ] Android client
- [ ] iOS client
- [ ] OpenWRT package
- [ ] Performance testing vs standard WireGuard

**Deliverable:** Drop-in quantum-safe replacement for WireGuard VPN.

---

## Phase 4 — Ecosystem (Year 2+)

- [ ] IETF RFC submission for QShield TLS extensions
- [ ] Browser integration proposals (Chrome, Firefox)
- [ ] QShield DNS-over-HTTPS with PQC
- [ ] IoT device identity SDK
- [ ] Enterprise CA deployment tooling
- [ ] Hardware Security Module (HSM) integration guide

---

## How to Influence the Roadmap

This roadmap is not fixed. Open a [Discussion](../../discussions) to:
- Propose new features or reprioritize existing ones
- Volunteer to lead a phase or specific milestone
- Report that a milestone is blocked and needs help

The roadmap will be updated quarterly based on community input and progress.
