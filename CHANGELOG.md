# Changelog — zetrix-encryption-java

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
- `Mnemonic.generatePrivateKeys(mnemonics, hdPaths, KeyType)` overload — supports SM2; ED25519 default preserved

### Changed
- `pom.xml` Java source/target upgraded from 1.7 to **1.8**
- `pom.xml` added `org.bouncycastle:bcprov-jdk18on:1.80`; excluded `com.madgag.spongycastle:core` from `bitcoinj-core` to prevent classpath conflicts
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
