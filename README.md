![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) for Java

Simple cryptographically auditable identifiers and processors implemented in
pure Java with no external runtime dependencies.

## Overview

An OWID records that the entity operating a domain captured or generated a
payload at a date and time, with an ECDSA signature over the OWID and any
other OWIDs it was signed together with. OWIDs chain together to form
verifiable trees. The cryptography is ECDSA on the NIST P-256 curve (also
known as secp256r1 or prime256v1) with the SHA-256 hash.

Read the [OWID project](https://github.com/SWAN-community/owid) to learn more
about the concepts before looking into this implementation. This library
creates, signs, serializes, and verifies OWIDs.

## Scope of this implementation

- Pure JDK. The only build and test dependency is JUnit 5. There are no
  runtime dependencies, so the library is a single small JAR.
- Reading supports versions 1, 2, and 3. Writing and signing always use the
  current version, version 3.
- Private keys are imported from PKCS#8 ("PRIVATE KEY") PEM. The SEC1
  ("EC PRIVATE KEY") PEM form is not supported because the JDK cannot parse
  it without an additional ASN.1 provider. Keys exported by this library, and
  the keys used across the test fixtures, use PKCS#8 and SPKI, so this
  limitation does not affect interoperability.
- Public keys are imported from Subject Public Key Info ("PUBLIC KEY") PEM.
- The well known end point helpers return paths and bodies. They do not bind
  to any web framework.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain has no
separate encoded maximum, so the protocol alone is not an application input
limit for the complete envelope.

This library validates that the declared payload length agrees with the bytes
present before it sizes or copies the payload. A large declaration without
the corresponding bytes is malformed and is rejected without allocating the
declared size. A matching large payload is not malformed merely because it is
large, and parsing work and memory use scale with the bytes actually present.

The in-memory APIs remain subject to Java's signed `int` array indexing,
address-space and available-memory limits, so a single Java byte array cannot
represent every value allowed by the unsigned wire field. Applications
accepting untrusted OWIDs must choose limits suitable for their use case and
enforce them before buffering the binary form or decoding Base64. An
implementation capacity failure or an application policy rejection is
distinct from an invalid OWID.

For transport input, limit the complete HTTP body or encoded envelope; allow
for the domain and other OWID fields as well as the payload. After parsing,
`owid.getPayloadLength()` reports the actual payload size without copying it
and can be used for downstream policy. The parser cannot choose either limit
on behalf of the application.

## Installation

Build and install with Maven. The project targets Java 21.

```
mvn install
```

Then depend on it from another Maven project.

```xml
<dependency>
    <groupId>io.github.swan-community</groupId>
    <artifactId>owid</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

```java
import com.swancommunity.owid.Creator;
import com.swancommunity.owid.Crypto;
import com.swancommunity.owid.Owid;

import java.util.Collections;

// The creator operates a domain and holds the signing keys.
Crypto crypto = Crypto.generate();
Creator creator = Creator.create("example.com", crypto);

// Create and sign an OWID with a payload.
Owid owid = creator.signString("Hello World");

// Serialize to base 64 for storage or transmission.
String encoded = owid.asBase64();

// Later, or elsewhere, decode and verify with the public key.
Owid copy = Owid.fromBase64(encoded);
String publicPem = crypto.publicKeyPem();
boolean valid = copy.verifyWithPublicKey(publicPem, Collections.emptyList());
```

Chaining covers other OWIDs with the same signature. The same others, in the
same order, must be supplied when verifying as were supplied when signing.

```java
Owid root = creator.signString("root");

Owid party = new Owid();
party.setPayload("party".getBytes());
creator.signWithOthers(party, java.util.List.of(root));

// Verifies with the root as the single other, fails without it.
party.verifyWithCrypto(crypto, java.util.List.of(root)); // true
party.verifyWithCrypto(crypto, Collections.emptyList());  // false
```

## Interface

- `Owid` holds the version, domain, date to the minute in UTC, payload bytes,
  and signature bytes.
  - `Owid.fromBase64` and `Owid.fromByteArray` parse a signed OWID.
  - `asBase64` and `asByteArray` serialize a signed OWID.
  - `payloadAsString` decodes the payload as UTF-8. `payloadAsPrintable`
    returns zero padded lower case hexadecimal with no separator.
    `payloadAsBase64` returns the payload as base 64.
  - `verifyWithCrypto` and `verifyWithPublicKey` return whether the signature,
    covering this OWID and any others provided, is valid.
  - `ageMinutes` returns the minutes elapsed since creation.
- `Crypto` holds the keys.
  - `Crypto.generate` creates a new P-256 key pair.
  - `Crypto.newSignOnly` imports a PKCS#8 private key PEM. The public key is
    derived so the instance can also verify.
  - `Crypto.newVerifyOnly` imports an SPKI public key PEM.
  - `signByteArray` returns the 64 byte signature. `verifyByteArray` returns
    whether a signature is valid.
  - `publicKeyPem` and `privateKeyPem` export the keys as PEM text.
  - An empty, whitespace, or null PEM is rejected with a clear message rather
    than an opaque cryptography error.
- `Creator` binds a domain to a signing `Crypto`.
  - `sign` and `signWithOthers` set the OWID domain to the creator domain, the
    date to the current time, and the version to the current version, then
    sign.
  - `signString` and `signBytes` create and sign a new OWID.
- `Endpoints` provides framework agnostic helpers for the well known end
  points.
  - `creatorResponse` returns JSON with the fields `domain`, `name`,
    `publicKeySPKI`, and `contractURL`. The path is `/owid/api/v{n}/creator`.
  - `publicKeyResponse` returns the PEM. The path is
    `/owid/api/v{n}/public-key` with a `format` parameter of `spki` or `pkcs`.

## Data structure notes

A signed OWID serializes to bytes in this exact order. Multi byte integers are
little endian, except the version 1 date.

| Field          | Bytes               | Description                                                  |
|----------------|---------------------|--------------------------------------------------------------|
| Version        | 1                   | The byte version of the OWID. Always the first byte.         |
| Domain         | length + 1          | Domain associated with the creator, null (0) terminated.     |
| Date           | 4 (2 for version 1) | Minutes elapsed since 2020-01-01 UTC as an unsigned integer. |
| Payload length | 4                   | Number of bytes that form the payload.                       |
| Payload        | variable            | Bytes that form the payload, if any.                         |
| Signature      | 64                  | ECDSA P-256 signature as the r and s values concatenated.    |

Version 1 stored the date as a two byte big endian count of hours since the
base date. Version 2 and version 3 store a four byte little endian count of
minutes. Versions 1 and 2 are deprecated and supported for reading existing
data only.

The signature is stored as 64 raw bytes, the 32 byte big endian r value
followed by the 32 byte big endian s value (IEEE P1363 format). It is not
ASN.1 DER. The data covered by the signature is this OWID without its
signature, followed by the complete bytes, including signature, of each other
OWID in the order provided when signing.

An empty OWID is written as the single byte `0x00`. It marks an absent
optional OWID inside a larger byte array.

Base 64 decoding accepts the standard alphabet with or without the trailing
padding. Encoding always emits padding.

## Testing

Run the test suite with Maven.

```
mvn test
```

The tests round trip the canonical wire format vectors byte for byte, verify
cross language signed fixtures including the chained case, confirm that a
flipped signature byte fails verification, and cover the binary read and write
helpers, the crypto, the creator, and the end point helpers.

## License

Apache License 2.0. See the [LICENSE](LICENSE) file.
