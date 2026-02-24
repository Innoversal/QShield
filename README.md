<div align="center">

# 🛡️ QShield

### Quantum-Safe Security for the Entire Internet

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Early_Development-orange.svg)]()
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)
[![PQC](https://img.shields.io/badge/Cryptography-Post--Quantum-purple.svg)]()

**QShield** is an open-source initiative to protect the entire internet against quantum computing attacks — by replacing today's vulnerable cryptography (RSA, ECC) with NIST-standardized Post-Quantum algorithms across SSL/TLS, VPNs, Certificate Authorities, and network protocols.

[📄 Read the Whitepaper](docs/WHITEPAPER.md) · [🚀 Roadmap](docs/ROADMAP.md) · [🤝 Contributing](CONTRIBUTING.md) · [💬 Discussions](../../discussions)

</div>

---

## ⚠️ The Problem

Quantum computers running **Shor's Algorithm** will break RSA and ECC — the cryptographic foundation of today's internet — within the next 5–10 years.

This means:
- Every HTTPS connection will be decryptable
- VPN tunnels will be exposed
- Digital certificates will be forgeable
- Nation-states are **already collecting encrypted data today** to decrypt later ("Harvest Now, Decrypt Later")

**The internet needs a new cryptographic foundation. That is QShield.**

---

## 🎯 What QShield Does

QShield replaces vulnerable cryptography across three core layers:

### 1. 🔐 QShield TLS
Drop-in replacement for TLS 1.3 that adds a hybrid quantum-safe handshake using **CRYSTALS-Kyber** (key exchange) and **CRYSTALS-Dilithium** (signatures). Backward compatible with existing infrastructure.

### 2. 📜 QShield CA (Certificate Authority)
A free, automated, open Certificate Authority — like **Let's Encrypt, but quantum-safe**. Issues hybrid X.509 certificates signed with Dilithium instead of RSA.

### 3. 🌐 QShield VPN
A WireGuard-based VPN protocol upgraded with Post-Quantum key exchange. Protects all network-level traffic against quantum attacks.

---

## 🔬 Cryptographic Foundation

All QShield components use **NIST-standardized Post-Quantum algorithms** (finalized 2024):

| Purpose | Algorithm | Standard |
|---|---|---|
| Digital Signatures | CRYSTALS-Dilithium 3 | FIPS 204 |
| Key Encapsulation | CRYSTALS-Kyber 768 | FIPS 203 |
| Hashing | SHA3-256 / SHAKE256 | FIPS 202 |
| Symmetric Encryption | AES-256-GCM | FIPS 197 |

Hybrid mode combines classical (ECDH) + post-quantum (Kyber) for protection against both classical and quantum attackers simultaneously.

---

## 🗺️ Roadmap

| Phase | Goal | Status |
|---|---|---|
| Phase 1 | QShield TLS Library (hybrid handshake) | 🔲 Planning |
| Phase 2 | QShield CA (free PQ certificates) | 🔲 Planning |
| Phase 3 | QShield VPN (WireGuard + Kyber) | 🔲 Planning |
| Phase 4 | Browser integration & IETF proposal | 🔲 Future |

See [ROADMAP.md](docs/ROADMAP.md) for full details.

---

## 🤝 How to Contribute

QShield needs contributors across many disciplines:

- **Cryptographers** — Review and improve PQC implementation
- **Systems Engineers** — Build TLS and VPN components
- **Security Researchers** — Threat modeling and audit
- **DevOps / Infra** — CA infrastructure design
- **Technical Writers** — Documentation

Read [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

---

## 📄 Documentation

- [Whitepaper](docs/WHITEPAPER.md) — Full technical design
- [Roadmap](docs/ROADMAP.md) — Development phases
- [Architecture](docs/ARCHITECTURE.md) — System design diagrams
- [Contributing](CONTRIBUTING.md) — How to contribute

---

## 📜 License

Apache 2.0 — free for everyone, forever.

---

<div align="center">
<b>The quantum threat is real. QShield is the answer.</b><br>
<i>Built in public, for everyone.</i>
</div>
