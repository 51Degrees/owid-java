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
- Fetching the public key of another creator uses `HttpURLConnection` from
  the JDK, so verifying over the network adds no dependency and still runs on
  Java 8.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain is capped
at 253 characters, so that field is at most 254 bytes with its terminator,
which leaves the payload as the only part of the envelope the protocol leaves
open ended, so the protocol alone is not an application input limit for the
complete envelope.

This library validates that the declared payload length agrees with the bytes
present before it sizes or copies the payload. A large declaration without
the corresponding bytes is malformed, and is reported as
`BYTE_COUNT_MISMATCH` on the whole buffer read, or as `UNEXPECTED_END` on the
framed read, without allocating the declared size either way. A matching large
payload is not malformed merely because it is large, and parsing work and
memory use scale with the bytes actually present.

The 253 character maximum binds this library on both sides. A buffer whose
domain field runs past it is refused when it is read, and a domain longer than
it is refused when a `Creator` is built and again when the domain is written,
so the library will not emit an OWID that it would then refuse to read.

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

Build and install with Maven. The library is compiled for Java 8, and the
test suite runs on Java 8, 11, 17 and 21.

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

The example below is compiled and run by the test suite as
`ReadmeExampleTest`, so a change to the library that would break it fails the
build rather than leaving a documented example that no longer works.

```java
import com.swancommunity.owid.Creator;
import com.swancommunity.owid.Crypto;
import com.swancommunity.owid.Owid;
import com.swancommunity.owid.OwidParseResult;

import java.util.Collections;

// The creator operates a domain and holds the signing keys.
Crypto crypto = Crypto.generate();
Creator creator = Creator.create("example.com", crypto);

// Create a signed OWID with a payload. An OWID is signed from the moment it
// exists, so there is never an unsigned one to hold.
Owid owid = creator.createString("Hello World");

// Serialize to base 64 for storage or transmission.
String encoded = owid.asBase64();

// Later, or elsewhere, read it back. Reading answers rather than throwing,
// because whatever arrives from outside may not be an OWID at all.
OwidParseResult result = Owid.parse(encoded);
if (result.isSuccess()) {
    Owid copy = result.getValue();
    String publicPem = crypto.publicKeyPem();
    boolean valid = copy.verifyWithPublicKey(
        publicPem, Collections.<Owid>emptyList());
} else {
    // result.getStatus() names which of the expected problems it was, and
    // result.getValue() is null.
}
```

Chaining covers other OWIDs with the same signature. The same others, in the
same order, must be supplied when verifying as were supplied when signing.

```java
Owid root = creator.createString("root");
Owid party = creator.createString("party", Collections.singletonList(root));

// Verifies with the root as the single other, fails without it.
party.verifyWithCrypto(crypto, Collections.singletonList(root)); // true
party.verifyWithCrypto(crypto, Collections.<Owid>emptyList());   // false
```

## Verifying an identifier signed in an earlier week

Creators rotate their signing key, weekly in the case of the 51Degrees cloud,
so the key that is current when an identifier is checked is not the key that
signed the identifier unless the check happens in the same week. Verifying
anything older than a few days means asking for the key that was in force on
the date the identifier carries.

`PublicKeyFetch` asks the creator for that key. The request is
`/owid/api/v{n}/public-key?date={minutes}&format=pkcs`, where the version in
the path is the version byte of the identifier being checked and the minutes
are counted from 2020-01-01 in the same way the identifier stores its date. A
creator that ignores the parameter returns its current key, so every
identifier it signed under an earlier key reads as not matching, which is why
a creator that rotates its key has to honour the date. Keys already fetched
are held against the URL they came from, which names the domain, the version
and the minute, up to 1024 of them before the store is emptied, and
`clearCache` empties it on demand.

```java
import com.swancommunity.owid.OwidSignatureStatus;
import com.swancommunity.owid.OwidVerificationResult;
import com.swancommunity.owid.PublicKeyFetch;

OwidVerificationResult result = PublicKeyFetch.verify(
    owid, "https", Collections.<Owid>emptyList());
if (result.getStatus() == OwidSignatureStatus.KEY_UNAVAILABLE) {
    // The key could not be obtained, so the signature was never examined.
    // Only SIGNATURE_INVALID means the identifier should be distrusted.
}
```

Where the whole published schedule is already held, `PublicKeySchedule`
chooses the key without any request. The rule is the one the cloud itself
applies, being the latest key whose start is at or before the date asked
about.

```java
import com.swancommunity.owid.DatedPublicKey;
import com.swancommunity.owid.PublicKeySchedule;

PublicKeySchedule schedule = PublicKeySchedule.of(Arrays.asList(
    DatedPublicKey.of(Instant.parse("2026-08-24T00:00:00Z"), lastWeekPem),
    DatedPublicKey.of(Instant.parse("2026-08-31T00:00:00Z"), thisWeekPem)));
OwidVerificationResult result = schedule.verify(
    owid, Collections.<Owid>emptyList());
```

Both snippets are compiled and run by `ReadmeExampleTest`, as the rest of
the examples in this file are. The fetch one runs against a creator domain in
the reserved `.invalid` name space, so it shows the shape of the call and the
status a key that cannot be obtained produces, whilst the case where the key
does arrive and the identifier verifies is covered by `DatedKeyFetchTest`
against a stand in on the loopback address.

The only date a key carries here is the date the key came into force. The
moment key material was generated is deliberately absent, because creators
generate keys in batches weeks ahead of the weeks the keys cover, so many
keys share one generation moment while starting on different days. Choosing
by the generation moment picks a key that has not started yet and reports a
genuine identifier as not matching, which is the defect the .NET port
carried. The fixture the tests run against holds thirteen real keys generated
in one batch, so that rule is shown failing on real data and the rule this
library uses is shown succeeding on the same data.

## Reading, and why it does not throw

An OWID is read from whatever a caller was handed, which on a public end
point means anything at all, so malformed data is an ordinary outcome rather
than an exceptional one. `Owid.parse`, overloaded on the encoded string, the
raw bytes and a `ByteBuffer`, therefore reports three facts every time.

| Fact | Where |
|------|-------|
| Whether it worked | `isSuccess()` |
| The OWID, only when it worked | `getValue()`, null otherwise |
| A named reason, either way | `getStatus()` |

The statuses are the cross language vocabulary, so a failure means the same
thing whichever language read the bytes.

| Status | Meaning |
|--------|---------|
| `PARSED` | The bytes are a structurally valid OWID. |
| `MISSING_INPUT` | Nothing was supplied to read. |
| `INVALID_INPUT_TYPE` | Not reachable in Java, where the compiler already refuses anything that is not a string or a byte array. |
| `INVALID_BASE64` | The string is not base 64, so there are no bytes to read. |
| `UNSUPPORTED_VERSION` | The first byte names a version this library does not know. Version zero is known, and is `ABSENT_NODE` below. |
| `UNEXPECTED_END` | The data stopped in the middle of a field. Reading a frame, this also covers a frame running past the bytes supplied. |
| `INVALID_DOMAIN_ENCODING` | The domain is unterminated, or longer than the published maximum. |
| `BYTE_COUNT_MISMATCH` | The declared payload count disagrees with the bytes present. Only the whole buffer read reports it. |
| `IMPLEMENTATION_CAPACITY_EXCEEDED` | Larger than this runtime can hold. Not reachable from the byte array surface, because a Java array cannot exceed `Integer.MAX_VALUE` bytes and so can never agree with a larger declaration. |
| `MALFORMED_ENVELOPE` | Malformed in a way none of the others describes. Nothing reaches it, because the byte count rule already refuses everything it would catch, and it is kept as a backstop so a later change to that arithmetic cannot start accepting bytes after the signature in silence. |
| `ABSENT_NODE` | The bytes are the marker for an absent optional OWID, on both reading contracts. Not a fault and not an OWID, so no value is handed back. |

Reading and verifying are separate questions, and reading fetches no key and
performs no cryptography. Bytes that are a well formed OWID read successfully
even when the signature does not match, and only `verify` then
reports that it does not.

`verify` returns an `OwidVerificationResult` and keeps "does not match"
apart from "could not check", because
a key that cannot be obtained or cannot be decoded leaves the signature
unjudged, and reporting that as invalid would read as an attack rather than
as the outage it is.

| Status | Meaning |
|--------|---------|
| `SIGNATURE_VALID` | Genuine for this data and this key. |
| `SIGNATURE_INVALID` | Well formed and does not match. The only status that means the identifier should be distrusted. |
| `INVALID_SIGNATURE_LENGTH` | A signature field of the wrong length reached the check. A consumer cannot produce one, because reading and creation both settle the signature at 64 bytes. |
| `KEY_UNAVAILABLE` | No key was supplied, or the one supplied cannot verify. |
| `INVALID_KEY` | Key material arrived and cannot be decoded or used. |
| `IMPLEMENTATION_CAPACITY_EXCEEDED` | More work than this runtime can hold, which needs an OWID and its chain to approach the two gigabyte limit of a Java array. |
| `VERIFICATION_ERROR` | The check could not be completed for a reason that is not the identifier's fault. |

## Reading one OWID out of something longer

`Owid.parse(ByteBuffer)` is the framed read, for input that carries an OWID
inside something longer, such as a tree of them or a record with other fields
around it. It differs from the whole buffer read in one place. A whole buffer
has to end where the envelope does, so a byte after the signature belongs to
no field and is `BYTE_COUNT_MISMATCH`, whereas a frame only requires the
declared payload and the signature to be present and says nothing about what
follows, because what follows is the next frame rather than rubbish.

```java
ByteBuffer buffer = ByteBuffer.wrap(bytes);
while (buffer.hasRemaining()) {
    OwidParseResult result = Owid.parse(buffer);
    if (result.isSuccess() == false) {
        // buffer is still at the start of the frame that failed, and
        // result.getStatus() says why.
        break;
    }
    use(result.getValue());
}
```

On success the buffer moves on to the first byte after the envelope, so
calling `parse` again reads the next one, and `getByteCount()` on the result
reports how far it moved. On failure the buffer is left exactly where it was
and nothing is consumed, because a half read frame leaves a caller somewhere
it cannot reason about, so what to do with a bad frame is the caller's to
decide.

`UNEXPECTED_END` from the framed read means the frame runs past the bytes
supplied, so a caller reading from a source that is still arriving can wait
for more and read again from the same position. That is the settled rule
across every implementation rather than a choice this one made, because
knowing whether to wait for more bytes or to give up on these is what a
caller of a framed read most needs to be told.

An absent node marker in the middle of a run of frames reports `ABSENT_NODE`
and consumes its single byte, so the loop above steps over it and reads the
frame after it. It hands back no OWID, because the marker carries no
signature.

Buffers that carry no array a caller may reach, being direct and read only
ones, are read from a copy of what remains rather than in place. Callers
wrapping an array, which is the ordinary case, are read without any copy.

## How an OWID comes into being

An OWID is only worth anything because it is signed, so a caller cannot build
one. There is no public constructor and no setter, and an instance reaches
calling code by exactly two routes.

1. A successful read of a complete serialized OWID, through any `Owid.parse`
   overload.
2. A creator signing one into existence, through `createString` or
   `createBytes`.

An unsigned OWID is indistinguishable from a signed one to the code
downstream of it, and the difference only surfaces later when a verification
fails somewhere nobody is watching, which is why there is no way to obtain
one. There is no public way to sign an OWID either, because with nothing
unsigned to hold there is nothing outside to sign, and signing a parsed OWID
again would replace the signature its fields were read with.

The fields are read only for the same reason. The signature covers them as
they arrived, so a caller changing one afterwards would hold something the
signature no longer describes. `getPayload` and `getSignature` hand back
copies, because a Java byte array is mutable.

## Migrating from the earlier surface

| Before | After |
|--------|-------|
| `Owid.fromBase64(value)` | `Owid.parse(value)` |
| `Owid.fromByteArray(buffer)` | `Owid.parse(buffer)` |
| `new Owid()`, then `setPayload`, then `creator.sign(owid)` | `creator.createBytes(payload)` |
| `creator.signString(value)` | `creator.createString(value)` |
| `creator.signBytes(value)` | `creator.createBytes(value)` |
| `new Owid()`, then `creator.signWithOthers(owid, others)` | `creator.createBytes(payload, others)` |
| `owid.setVersion`, `setDomain`, `setDate`, `setPayload` | no replacement, the state is read only |
| `Version.fromByte(b)` | no replacement, an unknown version byte is `UNSUPPORTED_VERSION` from a read, and version zero is `ABSENT_NODE` |

`Owid.parse` is overloaded on the input type, so a caller passing a literal
`null` has to say which one it means, as in `Owid.parse((String) null)`. The
same is true of `verify`.

The parse surfaces do not throw for malformed data, so a caller that wrapped
the old ones in `try`/`catch` reads the status instead. `OwidException` is
still raised for the caller's own mistakes, such as an invalid creator
domain, a null payload, or a field that cannot be serialized.

## Interface

- `Owid` holds the version, domain, date to the minute in UTC, payload bytes,
  and signature bytes, all read only.
  - `Owid.parse` reads a signed OWID, from the encoded string, from the raw
    bytes, or from a `ByteBuffer` holding one frame of something longer, and
    reports why rather than throwing. `getByteCount` on the result says how
    many bytes the envelope occupied.
  - `asBase64` and `asByteArray` serialize a signed OWID.
  - `payloadAsString` decodes the payload as UTF-8. `payloadAsPrintable`
    returns zero padded lower case hexadecimal with no separator.
    `payloadAsBase64` returns the payload as base 64. `getPayloadLength`
    reports the payload size without copying it.
  - `verifyWithCrypto` and `verifyWithPublicKey` return whether the signature,
    covering this OWID and any others provided, is valid.
  - `verify`, taking either the `Crypto` or the public key PEM, answers the
    same question with a status, keeping a key that could not be used apart
    from a signature that does not match.
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
  - `createString` and `createBytes` create a complete signed OWID, setting
    the domain to the creator domain, the date to the current time and the
    version to the current version. Both take an optional list of other OWIDs
    to cover with the same signature.
- `PublicKeyFetch` obtains the key of another creator from the well known end
  point on the domain the OWID carries.
  - `publicKeyUrl` builds the request, naming the version of the OWID and the
    minute the OWID was signed.
  - `publicKeyPem` returns the key, raising `PublicKeyFetchException`, which
    carries the status to report, the domain and the response code.
  - `verify` answers with the status, so a key that could not be fetched is
    `KEY_UNAVAILABLE`, one that could not be read is `INVALID_KEY`, and
    neither is mistaken for a signature that does not match.
  - `clearCache` empties the keys already fetched.
- `PublicKeySchedule` holds the keys a creator has published and chooses
  between them.
  - `PublicKeySchedule.of` takes the keys in any order.
  - `keyInForce` and `keyFor` return the latest key whose start is at or
    before the date, or the date of the OWID, and null where the schedule
    does not reach back that far.
  - `current` returns the key in force now, and `last` the key with the
    latest start, which for a schedule published ahead of time is usually a
    key that has not begun. `verify` chooses the key and answers with the
    status.
- `DatedPublicKey` is one key and the date the key came into force. It holds
  no generation moment, so nothing can select by one.
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

An absent optional OWID is written as the single byte `0x00`, which
`Owid.emptyByteArray` produces, and it marks the absence of a node inside a
larger framed byte array. Reading it reports `ABSENT_NODE` and hands back no
OWID, because the marker carries no signature and returning one would put an
OWID in a caller's hands that nothing had ever signed. It is not a fault
either, since version zero is supported and what it means is that a node is
missing. The first byte settles this on both reading contracts, because
nothing after it can turn the value into an OWID. Read as a frame the marker
is also consumed, so a caller steps over the absent node and reads the frame
after it.

Base 64 decoding accepts the standard alphabet with or without the trailing
padding, and skips line breaks and spaces. Anything else in the string is
reported as `INVALID_BASE64`. Encoding always emits padding.

## Testing

Run the test suite with Maven.

```
mvn test
```

The tests round trip the canonical wire format vectors byte for byte, verify
cross language signed fixtures including the chained case, confirm that a
flipped signature byte fails verification, and cover the binary write
helpers, the crypto, the creator, and the end point helpers. They also cover
the parse contract, being every status the reading surfaces report together
with a run of malformed buffers that must never throw, the framed read and
what it consumes, and the construction boundary, which is checked from a package outside the library because a check
made from inside it would measure nothing.

The dated key tests use two real fixtures, being a 51Did creator context
identifier created on 4 September 2026 for the creator domain 51d.es and the
thirty weekly keys that domain published from 11 May to 30 November 2026.
Both are public and carry no secret. The live end point answers 401 without a
credential, so the fetch runs against a stand in on the loopback address
which serves that same schedule, and the URL under test is the one the
library builds with only the host replaced.

## License

Apache License 2.0. See the [LICENSE](LICENSE) file.
