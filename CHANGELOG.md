# Changelog — zetrix-encryption-java

## [Unreleased]

### Security
- **Invalid private key errors no longer include the key.** Loading a malformed private key (wrong prefix, type byte or checksum) threw `Private key (<key>) is invalid`, so a key with a typo could end up in any log that records the exception. The message is now always `Invalid privateKey`. Invalid public keys likewise give `Invalid publicKey` without echoing the input, so a private key passed where a public key is expected (for example to `PrivateKey.getEncAddress(String)`) is not logged either.
- **SM2 signatures must be exactly 64 bytes.** `PublicKey.verify` for SM2 read only the first 64 bytes, so a valid signature with extra bytes appended still verified. Signatures of any other length are now rejected, as they already were for ED25519, Dilithium3 and Hybrid.

### Fixed
- Loading a private key from its encoded string (`new PrivateKey(String)`, `PrivateKey.sign(msg, key)`, `PrivateKey.getEncPublicKey(key)`) now checks the key length for its type, as `isPrivateKeyValid` already did. A shortened or lengthened key with a valid checksum is rejected instead of loading with a wrong public key and address.
- Dilithium3 and Hybrid private keys: the Dilithium3 public key stored in the key must belong to its secret key (checked against the public-key hash `tr` inside the secret key). Both loading and `isPrivateKeyValid` reject a key that pairs a secret key with another key's public key.
- `addressPrefix` test: SM2 addresses start with `ZTX3` or, for about 1 in 8 keys, `ZTX4`. The test accepted only `ZTX3` and failed at random. The README key table now lists both.

### Added
- Tests: malformed-key error message, wrong-length keys with a valid checksum, mismatched Dilithium3 key pair, and wrong-length signatures (appended, truncated, empty) for all four key types.

---

## [1.2.0.RELEASE] — 2026-11-20

### Security
- **HTTPS certificate and hostname checks are now on**. `HttpKit` used a TrustManager that accepted any certificate and a HostnameVerifier that accepted any hostname, so HTTPS calls could be intercepted by anyone on the network path. `HttpKit` now uses the JVM's default trust store and hostname verification. A server with an expired, self-signed, untrusted or wrong-host certificate is refused with an `SSLHandshakeException`. See "HTTPS and node certificates" in the README for private-CA nodes.

### Removed
- **`org.zetrix.encryption.utils.http.Verifier`** (breaking). It was the always-true HostnameVerifier. Remove any use of it and rely on default hostname verification. `zetrix-sdk` 1.1.0.RELEASE and earlier use this class: upgrade to `zetrix-sdk` 1.1.1.RELEASE together with this version, otherwise the old SDK fails with `NoClassDefFoundError` on its first HTTPS call.

### Added
- `HttpKitTlsTest` — rejects self-signed and wrong-hostname certificates, accepts a trusted certificate for the right hostname.

---

## [1.1.0.RELEASE] — 2026-04-21

### Added
- **SM2** key type (`KeyType.SM2`) — Bouncy Castle `sm2p256v1`; raw `r||s` 64-byte signature (no DER); SM3 message pre-hash; address prefix `ZTX3`
- **Dilithium3** key type (`KeyType.DILITHIUM3`) — Bouncy Castle 1.80 ML-DSA-65 (FIPS 204); `CRHBYTES=64`; 4,032-byte private key; 3,309-byte signature; address prefix `ZTX4`
- **Hybrid** key type (`KeyType.HYBRID`) — ED25519 + Dilithium3 concatenation; 6,016-byte private key; 3,373-byte signature; address prefix `ZTX5`
- `KeyType.fromSignTypeByte()` and `KeyType.fromAddressByte()` static lookups replacing fragile ordinal arithmetic
- `SM2Helper.java` — SM2 key generation, derivation, sign, verify
- `Dilithium3Helper.java` — ML-DSA-65 key generation, sign (`internalGenerateSignature` via reflection, matching `sign_internal` on the blockchain node), verify
- `HybridHelper.java` — Hybrid key generation, sign, verify; both sub-signatures required for verification
- `KeyStore.generateKeyStore(password, privKey, KeyType, version)` overload — supports all four key types; original signature preserved for backward compatibility
- `Mnemonic.generatePrivateKeys(mnemonics, hdPaths, KeyType)` overload — ED25519 only; throws `UnsupportedOperationException` for PQC types (BIP32 derivation is only meaningful for ED25519)

### Changed
- `pom.xml` Java source/target upgraded from 1.7 to **1.8**
- `pom.xml` added `org.bouncycastle:bcprov-jdk18on:1.80` (version pinned as `[1.80]` to prevent accidental BC upgrades breaking the reflection-based `internalGenerateSignature` call)
- `CheckKey.CalHash()` — now dispatches SM3 for SM2, SHA-256 for all other types (previously used SHA-256 only or had an incorrect `else→SM3` branch)
- `PrivateKey.encPrivateKey()` / `encPublicKey()` — replaced `type.ordinal()+1` with `type.getSignTypeByte()`
- `PrivateKey.encPrivateKeyValid()` / `getPrivateKey()` — removed hardcoded ED25519-only length and type byte checks; accept variable-length keys; whitelist type bytes `{0x01, 0x02, 0x05, 0x06}`
- `PublicKey.getPublicKey()` — replaced `values()[byte-1]` ordinal lookup with `fromSignTypeByte()` scan
- `PublicKey.encAddress()` — uses `type.getAddressByte()` (Dilithium3 address byte `0x04` ≠ sign type `0x05`)
- `PublicKey.encPublicKeyValid()` / `encAddressValid()` — whitelist valid sign bytes and address bytes; type-aware `CalHash`

### Fixed
- Dilithium3 signing incompatibility with Zetrix blockchain node: Bouncy Castle 1.80's `MLDSASigner.init()` prepends a FIPS 204 pure-mode context byte sequence (`0x00 || 0x00`) to the message digest. The blockchain uses `sign_internal` directly (no prefix). Fixed by calling the protected `internalGenerateSignature` / `internalVerifySignature` methods via reflection — these use `initSign(tr, false, null)` which skips the context prefix entirely.

---

## [1.0.0] — (prior release)

- ED25519 only
