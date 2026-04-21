# Zetrix Encryption Java

Java cryptographic library for the Zetrix blockchain. Supports four key algorithms — **ED25519**, **SM2**, **Dilithium3 (ML-DSA-65 / FIPS 204)**, and **Hybrid (ED25519 + Dilithium3)**.

## Contents

| Directory | Description |
|-----------|-------------|
| [`src/`](src/) | Library source code and `pom.xml` |
| [`examples/`](examples/) | Standalone Maven example project |

## Requirements

- Java 8 or above (JDK 8–21 tested)
- Maven 3.x

## Installation

### Maven

```xml
<dependency>
  <groupId>org.zetrix.encryption</groupId>
  <artifactId>zetrix-encryption</artifactId>
  <version>1.1.0.RELEASE</version>
</dependency>
```

### JAR

Download `zetrix-encryption-1.1.0.RELEASE.jar` from `libs/` and add it to your project classpath along with the bundled dependencies.

## Supported Algorithms

| Algorithm | Key Type Constant | Address Prefix | Private Key | Public Key | Signature |
|-----------|-------------------|----------------|-------------|------------|-----------|
| ED25519 | `KeyType.ED25519` | `ZTX3` | 32 B | 32 B | 64 B |
| SM2 | `KeyType.SM2` | `ZTX3` | 32 B | 65 B | 64 B |
| Dilithium3 (ML-DSA-65) | `KeyType.DILITHIUM3` | `ZTX4` | 4,032 B | 1,952 B | 3,309 B |
| Hybrid (ED25519 + Dilithium3) | `KeyType.HYBRID` | `ZTX5` | 6,016 B | 1,984 B | 3,373 B |

> **Dilithium3** uses FIPS 204 ML-DSA-65 (`CRHBYTES=64`). The implementation calls `sign_internal` directly (matching the Zetrix blockchain node and Node.js SDK) — no FIPS 204 pure-mode context prefix is applied.

## Quick Start

### Generate a key pair

```java
import org.zetrix.encryption.key.PrivateKey;
import org.zetrix.encryption.model.KeyType;

// ED25519 (default)
PrivateKey ed25519Key = new PrivateKey(KeyType.ED25519);

// SM2
PrivateKey sm2Key = new PrivateKey(KeyType.SM2);

// Dilithium3 (post-quantum)
PrivateKey dil3Key = new PrivateKey(KeyType.DILITHIUM3);

// Hybrid (post-quantum + classical)
PrivateKey hybridKey = new PrivateKey(KeyType.HYBRID);

String encPrivKey = dil3Key.getEncPrivateKey();  // Base58-encoded private key
String encPubKey  = dil3Key.getEncPublicKey();   // Hex-encoded public key
String address    = dil3Key.getEncAddress();     // ZTX4... address
```

### Sign and verify

```java
byte[] message   = "hello zetrix".getBytes();
byte[] signature = dil3Key.sign(message);

boolean ok = dil3Key.getPublicKey().verify(message, signature);
// ok == true
```

### Load from an encoded private key string

```java
PrivateKey key = new PrivateKey("YOUR_PRIVATE_KEY");
byte[] sig = key.sign(message);
```

### KeyStore

```java
import org.zetrix.encryption.crypto.keystore.KeyStore;

// Encrypt
KeyStoreEty ks = KeyStore.generateKeyStore("password", encPrivKey, KeyType.DILITHIUM3, 44);

// Decrypt
String recovered = KeyStore.decipherKeyStore("password", ks);
```

### Mnemonic

```java
import org.zetrix.encryption.crypto.mnemonic.Mnemonic;

List<String> words   = Mnemonic.generateMnemonic(16);
List<String> hdPaths = Arrays.asList("m/44'/526'/1'/0/0");

// ED25519 (default)
List<String> keys = Mnemonic.generatePrivateKeys(words, hdPaths);

// SM2
List<String> sm2Keys = Mnemonic.generatePrivateKeys(words, hdPaths, KeyType.SM2);
```

> **Note:** Mnemonic/HD derivation for Dilithium3 and Hybrid is an SDK-only feature. The Zetrix blockchain does not support HD derivation for PQC key types — keys generated from a mnemonic cannot be recovered on-chain.

## Running the Examples

```bash
cd examples
mvn compile exec:java -Dexec.mainClass="org.zetrix.encryption.example.TestKey"
```

## Running Tests

```bash
cd src
mvn test
```

The parameterized `EncryptionTest` suite covers key generation, encoding/decoding, sign/verify, keystore, and address derivation for all four key types.

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `bcprov-jdk18on` | 1.80 | SM2, ML-DSA-65 (Dilithium3), SHA-256, SM3 |
| `eddsa` (i2p) | 0.1.0 | ED25519 signing |
| `bitcoinj-core` | 0.14.7 | Base58, BIP39 mnemonic |
