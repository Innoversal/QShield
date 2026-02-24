# QShield Whitepaper
## Quantum-Safe Security Infrastructure for the Internet

**Version:** 1.0.0  
**Status:** Draft — Open for Community Review  
**Date:** February 2026

---

## Abstract

The widespread adoption of quantum computers capable of running Shor's Algorithm will render RSA and ECC cryptography — the foundation of modern internet security — completely insecure. This paper proposes **QShield**, an open-source, community-driven initiative to replace vulnerable cryptographic primitives across the internet's core security layers: TLS/SSL, Certificate Authorities, and VPN protocols. QShield uses NIST-standardized Post-Quantum Cryptography (PQC) algorithms, specifically CRYSTALS-Kyber and CRYSTALS-Dilithium, in a hybrid construction that protects against both classical and quantum adversaries simultaneously. QShield aims to be to Post-Quantum cryptography what Let's Encrypt was to HTTPS adoption — a free, automated, open infrastructure that makes quantum-safe security universally accessible.

---

## 1. Introduction

### 1.1 The Quantum Threat

In 1994, Peter Shor demonstrated that a sufficiently powerful quantum computer could factor large integers in polynomial time, breaking RSA encryption. Similarly, the Discrete Logarithm Problem underlying ECC can be solved efficiently by quantum computers. While current quantum computers are not yet capable of breaking production cryptography, rapid progress in the field makes this a near-term engineering certainty rather than a distant theoretical concern.

Conservative estimates place cryptographically relevant quantum computers within 5–15 years. More critically, adversaries — particularly nation-states — are engaged in "Harvest Now, Decrypt Later" (HNDL) attacks: collecting encrypted internet traffic today with the intention of decrypting it once quantum capability matures. This means the security of data encrypted today is already compromised for any information requiring long-term confidentiality.

### 1.2 The Gap in Current Solutions

NIST completed its Post-Quantum Cryptography standardization process in 2024, publishing FIPS 203 (Kyber), FIPS 204 (Dilithium), and FIPS 205 (SPHINCS+). However, adoption remains fragmented:

- Cloudflare and Google have conducted limited experiments with PQC in TLS
- No complete, self-hostable, open-source solution exists for full-stack quantum-safe infrastructure
- No free quantum-safe Certificate Authority exists for the broader internet
- VPN protocols have not been systematically upgraded

QShield addresses this gap by providing a complete, integrated, open-source quantum-safe security stack.

### 1.3 Design Philosophy

QShield is built on three principles:

**Openness.** All code, protocols, and cryptographic designs are public, auditable, and free. Security through obscurity is rejected.

**Compatibility.** QShield uses hybrid constructions that work alongside classical cryptography, enabling incremental adoption without breaking existing infrastructure.

**Simplicity.** Deployment should be as simple as Let's Encrypt. Complexity is the enemy of security adoption.

---

## 2. Threat Model

### 2.1 Adversary Classes

QShield considers two adversary classes:

**Classical Adversary:** A computationally bounded adversary with access to classical computers. Current TLS 1.3 with ECDH and RSA certificates provides adequate protection against this adversary. QShield maintains this protection.

**Quantum Adversary:** An adversary with access to a cryptographically relevant quantum computer capable of running Shor's Algorithm and Grover's Algorithm at scale. Against this adversary, RSA, ECC, and Diffie-Hellman provide no security. QShield is designed specifically to resist this adversary.

### 2.2 Attack Vectors Addressed

| Attack | Description | QShield Defense |
|---|---|---|
| Shor's Algorithm | Breaks RSA/ECC key pairs | Replaced by Dilithium + Kyber |
| Grover's Algorithm | Halves symmetric key security | AES-256 (maintains 128-bit PQ security) |
| Harvest Now Decrypt Later | Collect ciphertext for future decryption | Forward-secret Kyber KEM |
| Certificate Forgery | Forge certificates with broken RSA | Dilithium-signed certificates |
| Man-in-the-Middle | Intercept and modify traffic | Quantum-safe mutual authentication |
| Replay Attack | Replay captured authentication tokens | Nonce + expiry in all tokens |

### 2.3 Out of Scope

QShield does not address: side-channel attacks on hardware implementations, social engineering, compromised endpoint devices, or traffic analysis attacks. These require complementary security measures outside QShield's scope.

---

## 3. Cryptographic Primitives

### 3.1 CRYSTALS-Kyber (FIPS 203) — Key Encapsulation

Kyber is a lattice-based Key Encapsulation Mechanism (KEM) based on the hardness of the Module Learning With Errors (MLWE) problem. QShield uses Kyber-768, which provides approximately 180-bit classical security and is believed to provide 180-bit post-quantum security.

```
Kyber-768 Parameters:
  Public key size:  1184 bytes
  Secret key size:  2400 bytes
  Ciphertext size:  1088 bytes
  Shared secret:    32 bytes
```

Kyber replaces ECDH in QShield's TLS handshake and VPN key exchange.

### 3.2 CRYSTALS-Dilithium (FIPS 204) — Digital Signatures

Dilithium is a lattice-based digital signature scheme based on the hardness of MLWE and Module Short Integer Solution (MSIS). QShield uses Dilithium3, providing approximately 128-bit post-quantum security.

```
Dilithium3 Parameters:
  Public key size:  1952 bytes
  Secret key size:  4000 bytes
  Signature size:   3293 bytes
```

Dilithium replaces RSA and ECDSA in QShield certificates, TLS authentication, and all signing operations.

### 3.3 Hybrid Construction

QShield uses a hybrid construction for all key exchange operations, combining classical ECDH (P-256) with Kyber-768:

```
Hybrid_Secret = KDF(ECDH_Secret || Kyber_Secret)
```

This ensures that breaking QShield requires breaking **both** ECDH (classically hard) **and** Kyber (quantum-hard) simultaneously. An attacker with only a quantum computer or only a classical computer cannot break the hybrid construction.

---

## 4. QShield TLS

### 4.1 Overview

QShield TLS extends TLS 1.3 with Post-Quantum key exchange and authentication. It is implemented as:

- An OpenSSL provider (for server-side integration)
- A native TLS library (for client applications)
- A proxy module (for legacy application compatibility)

### 4.2 Handshake Protocol

```
Client                                          Server
  |                                               |
  |-- ClientHello -------------------------------->|
  |   supported_groups: [X25519Kyber768, X25519]  |
  |   signature_algorithms: [dilithium3, ecdsa]   |
  |                                               |
  |<-- ServerHello --------------------------------|
  |    selected_group: X25519Kyber768             |
  |    key_share: (X25519_share || Kyber_ct)      |
  |                                               |
  |<-- Certificate --------------------------------|
  |    Dilithium3 certificate chain               |
  |    (hybrid: also contains RSA for compat)     |
  |                                               |
  |<-- CertificateVerify --------------------------|
  |    Dilithium3 signature                       |
  |                                               |
  |<-- Finished -----------------------------------|
  |                                               |
  |-- Finished ----------------------------------->|
  |                                               |
  |========= Quantum-Safe Encrypted Session =======|
```

### 4.3 Hybrid Key Share

The `X25519Kyber768` key share combines X25519 ECDH with Kyber-768 KEM:

```
client_share = X25519_public || Kyber_public_key
server_share = X25519_public || Kyber_ciphertext

shared_secret = HKDF-SHA3-256(
  X25519_shared || Kyber_shared_secret,
  label = "qshield tls 1.0"
)
```

### 4.4 Performance Considerations

Post-Quantum algorithms have larger key and signature sizes than classical algorithms. Expected overhead:

| Metric | Classical TLS 1.3 | QShield TLS | Overhead |
|---|---|---|---|
| Handshake size | ~4 KB | ~12 KB | ~3x |
| Handshake time | ~1ms | ~2-3ms | ~2-3x |
| Certificate size | ~2 KB | ~6 KB | ~3x |
| Per-record overhead | 0 | 0 | None |

After the handshake, per-record overhead is identical to standard TLS 1.3 since symmetric encryption (AES-256-GCM) is unchanged.

---

## 5. QShield CA

### 5.1 Overview

QShield CA is a free, automated Certificate Authority that issues quantum-safe X.509 certificates. It is compatible with the ACME protocol (RFC 8555), meaning existing tools like Certbot work without modification.

### 5.2 Certificate Format

QShield CA issues hybrid certificates containing both:
- Classical RSA-2048 or ECDSA P-256 signature (for backward compatibility)
- Dilithium3 signature (for quantum resistance)

This hybrid approach allows QShield certificates to be verified by both classical and QShield-aware clients during the transition period.

### 5.3 Certificate Issuance Flow

```
1. Domain owner runs: qshield certbot --domain example.com
2. Client generates Dilithium3 keypair locally
3. Client submits CSR to QShield CA via ACME
4. QShield CA performs domain validation (HTTP-01 or DNS-01)
5. QShield CA issues hybrid certificate (RSA + Dilithium)
6. Certificate installed automatically
7. Auto-renewal every 60 days
```

### 5.4 CA Infrastructure

QShield CA is designed for high availability and decentralization:

- Root CA: Air-gapped, HSM-protected, offline signing
- Intermediate CAs: Geographically distributed (minimum 5 regions)
- OCSP Responders: Distributed, cached responses
- Certificate Transparency: Full CT logging to public logs

---

## 6. QShield VPN

### 6.1 Overview

QShield VPN is a WireGuard-based VPN protocol with the Diffie-Hellman key exchange replaced by a hybrid X25519+Kyber768 construction.

### 6.2 Handshake Modification

WireGuard's Noise_IKpsk2 handshake uses Curve25519 ECDH. QShield replaces this with:

```
# Standard WireGuard:
C := KDF(C, DH(Ephem_i, Static_r))

# QShield VPN:
(kyber_ct, kyber_ss) := Kyber.Encaps(peer_kyber_public)
C := KDF(C, DH(Ephem_i, Static_r) || kyber_ss)
```

Static keys include both Curve25519 and Kyber public keys. The combined shared secret is derived from both, maintaining WireGuard's security properties while adding quantum resistance.

### 6.3 Configuration

QShield VPN is a drop-in upgrade from WireGuard. The configuration format adds one field:

```ini
[Interface]
PrivateKey = <curve25519_private>
KyberPrivateKey = <kyber_private>    # New field
Address = 10.0.0.1/24

[Peer]
PublicKey = <curve25519_public>
KyberPublicKey = <kyber_public>      # New field
AllowedIPs = 0.0.0.0/0
```

---

## 7. Implementation Plan

### Phase 1 — QShield TLS Library (Months 1–4)
- Implement Kyber-768 and Dilithium-3 in C with constant-time guarantees
- Build OpenSSL 3.x provider
- Implement hybrid X25519Kyber768 key share for TLS 1.3
- Integration tests with Nginx, Apache, and curl
- Independent cryptographic audit

### Phase 2 — QShield CA (Months 5–9)
- Fork and extend Boulder (Let's Encrypt's CA software)
- Add Dilithium certificate issuance
- Deploy initial CA infrastructure
- Certbot plugin for automatic certificate management
- Public beta with real domain certificates

### Phase 3 — QShield VPN (Months 10–14)
- Fork WireGuard kernel module and userspace tools
- Implement hybrid handshake
- Android and iOS client applications
- Router firmware packages (OpenWRT)

### Phase 4 — Ecosystem (Year 2+)
- Browser integration proposals to Chrome, Firefox, Safari
- IETF RFC submission for QShield TLS extensions
- IoT device SDK
- Enterprise support tooling

---

## 8. Security Considerations

### 8.1 Hybrid Construction Rationale

Using hybrid classical+PQC construction is essential during the transition period because:

1. PQC algorithms are newer and have received less cryptanalysis than RSA/ECC
2. If a weakness in Kyber or Dilithium is discovered, classical algorithms provide a fallback
3. Hybrid mode maintains interoperability with non-QShield systems

### 8.2 Implementation Security

All cryptographic implementations must:
- Be constant-time to prevent timing side-channels
- Use secure memory allocation and zeroization
- Undergo independent security audit before production release
- Follow FIPS 140-3 guidelines where applicable

### 8.3 Key Management

- Private keys never leave the device that generated them
- Certificate private keys generated on user infrastructure, never transmitted to QShield CA
- Key rotation schedules: TLS certificates 60 days, CA intermediates 1 year, Root CA 20 years

---

## 9. Comparison with Related Work

| Project | PQ TLS | Free CA | PQ VPN | Open Source | Self-Hostable |
|---|---|---|---|---|---|
| **QShield** | ✅ Hybrid | ✅ Full | ✅ Hybrid | ✅ Apache 2.0 | ✅ Yes |
| Open Quantum Safe (liboqs) | ✅ Library | ❌ | ❌ | ✅ | ✅ |
| Cloudflare PQ | ✅ Partial | ❌ | ❌ | ❌ | ❌ |
| Let's Encrypt | ❌ Classical | ✅ Free | ❌ | ✅ | ✅ |
| WireGuard | ❌ Classical | ❌ | ❌ | ✅ | ✅ |
| Signal PQXDash | ❌ | ❌ | ❌ | ✅ | ❌ |

QShield is the only project targeting all three layers (TLS, CA, VPN) as an integrated, free, open-source, self-hostable system.

---

## 10. Conclusion

The transition to Post-Quantum cryptography is not optional — it is an engineering necessity that the internet must complete before cryptographically relevant quantum computers arrive. The window to act is now, while quantum computers are still being developed, before the harvest-and-decrypt attacks of today become active decryptions of yesterday's communications.

QShield provides the missing piece: a complete, integrated, free, open-source quantum-safe security stack that any website, network, or organization can deploy. By combining NIST-standardized PQC algorithms with hybrid constructions for backward compatibility and a Let's Encrypt-inspired deployment model for accessibility, QShield aims to accelerate internet-wide PQC adoption.

We invite cryptographers, security engineers, systems developers, and researchers to join the effort. The internet's quantum-safe future is a community project.

---

## References

1. NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (Kyber), 2024
2. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (Dilithium), 2024
3. NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (SPHINCS+), 2024
4. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
5. RFC 8555 — Automatic Certificate Management Environment (ACME)
6. Shor, P.W. (1994). Algorithms for quantum computation: discrete logarithms and factoring
7. Open Quantum Safe Project — https://openquantumsafe.org
8. WireGuard: Next Generation Kernel Network Tunnel — Jason A. Donenfeld, NDSS 2017

---

*This whitepaper is a living document. Community contributions, corrections, and improvements are welcome via GitHub pull requests.*
