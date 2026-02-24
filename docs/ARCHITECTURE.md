# QShield Architecture

This document describes the high-level architecture of QShield's three core components.

---

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        QShield Stack                                │
├──────────────────┬──────────────────────┬───────────────────────────┤
│   QShield TLS    │     QShield CA       │      QShield VPN          │
│                  │                      │                           │
│  Hybrid TLS 1.3  │  Free PQ Certificate │  WireGuard + Kyber KEM    │
│  X25519+Kyber    │  Authority (ACME)    │  Hybrid key exchange      │
│  Dilithium certs │  Dilithium signing   │  Quantum-safe tunnels     │
└──────────────────┴──────────────────────┴───────────────────────────┘
         │                    │                         │
         └────────────────────┴─────────────────────────┘
                              │
              CRYSTALS-Kyber + CRYSTALS-Dilithium
                    (NIST FIPS 203 / 204)
```

---

## QShield TLS Architecture

```
Application Layer
      │
      ▼
┌─────────────────────┐
│   QShield TLS API   │  ← Same interface as standard TLS
├─────────────────────┤
│  Hybrid Handshake   │  ← X25519 + Kyber768 combined
│  Record Layer       │  ← AES-256-GCM (unchanged)
│  Auth Layer         │  ← Dilithium3 certificates
├─────────────────────┤
│  OpenSSL Provider   │  ← Plugs into existing OpenSSL
├─────────────────────┤
│  liboqs             │  ← NIST PQC algorithm implementations
└─────────────────────┘
      │
      ▼
  TCP Socket
```

---

## QShield CA Architecture

```
                    ┌──────────────────┐
                    │   Root CA (HSM)  │  ← Air-gapped, offline
                    │  Dilithium Root  │
                    └────────┬─────────┘
                             │ signs
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Inter CA │  │ Inter CA │  │ Inter CA │  ← 5+ regions
        │ (Asia)   │  │ (Europe) │  │ (US)     │
        └─────┬────┘  └────┬─────┘  └────┬─────┘
              └────────────┼─────────────┘
                           │
                    ┌──────┴───────┐
                    │  ACME API    │  ← Standard ACME v2
                    │  (Boulder)   │
                    └──────┬───────┘
                           │
                  Domain Validation
                  (HTTP-01 / DNS-01)
                           │
                    ┌──────┴───────┐
                    │  Hybrid Cert │  ← RSA + Dilithium
                    │  (X.509)     │
                    └──────────────┘
```

---

## QShield VPN Architecture

```
Device A                                          Device B
┌─────────────────────┐                   ┌─────────────────────┐
│  Application        │                   │  Application        │
│  Traffic            │                   │  Traffic            │
├─────────────────────┤                   ├─────────────────────┤
│  QShield VPN        │                   │  QShield VPN        │
│  ┌───────────────┐  │                   │  ┌───────────────┐  │
│  │ Hybrid        │  │◄── Encrypted ────►│  │ Hybrid        │  │
│  │ Handshake     │  │    UDP Tunnel      │  │ Handshake     │  │
│  │ X25519+Kyber  │  │                   │  │ X25519+Kyber  │  │
│  └───────────────┘  │                   │  └───────────────┘  │
│  AES-256-GCM        │                   │  AES-256-GCM        │
└─────────────────────┘                   └─────────────────────┘
```

---

## Cryptographic Layer

All three components share a common cryptographic foundation:

```
┌────────────────────────────────────────────────────┐
│              QShield Crypto Core                   │
├──────────────┬─────────────────┬───────────────────┤
│  Kyber-768   │  Dilithium-3    │  Classical        │
│  (FIPS 203)  │  (FIPS 204)     │  (X25519, AES)    │
│  KEM         │  Signatures     │  Fallback/Hybrid  │
├──────────────┴─────────────────┴───────────────────┤
│                    liboqs                          │
│         (Open Quantum Safe library)                │
└────────────────────────────────────────────────────┘
```

---

## Key Sizes Reference

| Key Type | Classical | QShield PQ | Ratio |
|---|---|---|---|
| Public Key | 32B (X25519) | 1184B (Kyber) | ~37x |
| Private Key | 32B (X25519) | 2400B (Kyber) | ~75x |
| Signature | 64B (Ed25519) | 3293B (Dilithium) | ~51x |
| Certificate | ~2KB (RSA) | ~6KB (Hybrid) | ~3x |

These larger sizes are the primary performance cost of quantum safety. For TLS, they primarily affect the handshake (one-time cost), not ongoing data transfer.
