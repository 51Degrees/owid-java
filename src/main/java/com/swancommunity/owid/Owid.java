/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

package com.swancommunity.owid;

import java.io.ByteArrayOutputStream;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * OWID structure which can be used as a node in a tree.
 *
 * <p>An OWID records that the processor operating the domain handled the
 * payload, and any other OWIDs covered by the signature, at the date and time
 * given.</p>
 *
 * <p>An OWID is only worth anything because it is signed, so a caller cannot
 * build one. An instance reaches calling code by one of two routes, being
 * {@link #parse(String)}, {@link #parse(byte[])} or
 * {@link #parse(ByteBuffer)} reading bytes that were already a complete
 * OWID, or {@link Creator#createBytes(byte[])}
 * and its companions signing one into existence. There is deliberately no way
 * to assemble a half made one, because an unsigned OWID is indistinguishable
 * from a signed one to the code downstream of it and the difference only
 * surfaces later, when a verification fails somewhere nobody is watching.</p>
 *
 * <p>The state is read only for the same reason. The signature covers the
 * fields as they arrived, so a caller changing one afterwards would hold
 * something the signature no longer describes. The payload and signature are
 * handed out as copies, because a Java byte array is mutable and a caller
 * writing into one it was given would otherwise reach inside the OWID.</p>
 *
 * <p>The serialized form places the fields in this order. Multi byte integers
 * are little endian, except the version 1 date which is big endian.</p>
 *
 * <ul>
 *   <li>version: a single byte.</li>
 *   <li>domain: the UTF-8 bytes of the domain, null terminated, no longer
 *       than the maximum published for a domain name.</li>
 *   <li>date: four little endian bytes counting minutes since
 *       2020-01-01 UTC (two big endian bytes counting hours for version 1).</li>
 *   <li>payload: a four byte little endian length followed by the bytes.</li>
 *   <li>signature: 64 bytes, the r and s values concatenated. Nothing
 *       follows the signature.</li>
 * </ul>
 */
public final class Owid {

    /**
     * The length of an OWID signature in bytes. The ECDSA P-256 signature is
     * the 32 byte r value followed by the 32 byte s value.
     */
    public static final int SIGNATURE_LENGTH = 64;

    private final Version version;
    private final String domain;
    private final Instant date;
    private final byte[] payload;
    private final byte[] signature;

    /**
     * Builds an instance from fields a reader or the creator has already
     * settled.
     *
     * <p>Package private, so only this library can call it. That is the whole
     * construction boundary, because a consumer compiled against the library
     * cannot name this constructor at all, so there is no way to obtain an
     * OWID that has not either been read from a complete serialized one or
     * been signed by a {@link Creator}. The arrays are taken as given because
     * every caller inside the library hands over an array nothing else
     * holds.</p>
     */
    Owid(Version version, String domain, Instant date, byte[] payload,
            byte[] signature) {
        this.version = version;
        this.domain = domain;
        this.date = date;
        this.payload = payload;
        this.signature = signature;
    }

    /**
     * Reads a complete OWID from its base 64 form.
     *
     * <p>The value may be anything at all, because this is external data and
     * failing to be an OWID is an ordinary outcome rather than an error. The
     * result reports whether it worked, the OWID only when it did, and a
     * named reason either way. Decoding accepts the standard alphabet with or
     * without the trailing padding, and ignores line breaks and spaces.</p>
     *
     * <p>A successful read says the bytes are a structurally valid OWID. It
     * says nothing about whether the signature is genuine, which is a
     * separate question answered by {@link #verify(Crypto, List)}.</p>
     *
     * @param value the base 64 encoded OWID, which may be null
     * @return the OWID and {@link OwidParseStatus#PARSED}, or no value and
     *         the reason the string is not an OWID
     */
    public static OwidParseResult parse(String value) {
        if (value == null || value.isEmpty()) {
            return OwidParseResult.failed(OwidParseStatus.MISSING_INPUT);
        }
        byte[] buffer = OwidReader.decodeBase64(value);
        if (buffer == null) {
            return OwidParseResult.failed(OwidParseStatus.INVALID_BASE64);
        }
        return OwidReader.read(buffer, 0, buffer.length, false);
    }

    /**
     * Reads a complete OWID from a buffer holding exactly one.
     *
     * <p>The buffer must be one whole OWID and nothing else, so bytes after
     * the envelope are refused as {@link OwidParseStatus#BYTE_COUNT_MISMATCH}
     * because on this surface there is nothing else they could belong to. To
     * read one envelope out of something longer, and leave what follows for
     * the next read, use {@link #parse(ByteBuffer)}.</p>
     *
     * @param buffer the serialized OWID bytes, which may be null
     * @return the OWID and {@link OwidParseStatus#PARSED}, or no value and
     *         the reason the bytes are not an OWID
     */
    public static OwidParseResult parse(byte[] buffer) {
        if (buffer == null) {
            return OwidParseResult.failed(OwidParseStatus.MISSING_INPUT);
        }
        return OwidReader.read(buffer, 0, buffer.length, false);
    }

    /**
     * Reads one OWID from where the buffer is positioned, leaving whatever
     * follows for the next read.
     *
     * <p>This is the framed read, for input that carries an OWID inside
     * something longer, such as a tree of them or a record with other fields
     * around it. It differs from {@link #parse(byte[])} in one place only.
     * A whole buffer has to end where the envelope does, so a byte after the
     * signature belongs to no field, whereas here the declared payload and
     * the signature only have to be present and what follows is the next
     * frame rather than rubbish.</p>
     *
     * <p>On success the buffer is moved on to the first byte after the
     * envelope, so calling this again reads the next one, and
     * {@link OwidParseResult#getByteCount()} reports how far it moved. On
     * failure the buffer is left exactly where it was and nothing is
     * consumed, because a half read frame leaves a caller somewhere it cannot
     * reason about, so what to do with a bad frame is the caller's to
     * decide.</p>
     *
     * <pre>
     * ByteBuffer buffer = ByteBuffer.wrap(bytes);
     * while (buffer.hasRemaining()) {
     *     OwidParseResult result = Owid.parse(buffer);
     *     if (result.isSuccess() == false) {
     *         break;
     *     }
     *     use(result.getValue());
     * }
     * </pre>
     *
     * <p>{@link OwidParseStatus#UNEXPECTED_END} here means the frame runs
     * past the bytes supplied, so a caller reading from a growing source can
     * wait for more and read again from the same position.</p>
     *
     * @param buffer the bytes to read from, which may be null
     * @return the OWID and {@link OwidParseStatus#PARSED}, or no value and
     *         the reason the bytes are not an OWID
     */
    public static OwidParseResult parse(ByteBuffer buffer) {
        if (buffer == null || buffer.hasRemaining() == false) {
            return OwidParseResult.failed(OwidParseStatus.MISSING_INPUT);
        }
        OwidParseResult result;
        if (buffer.hasArray()) {
            int base = buffer.arrayOffset();
            result = OwidReader.read(buffer.array(),
                    base + buffer.position(), base + buffer.limit(), true);
        } else {
            // A direct or read only buffer has no array to walk, so the bytes
            // are taken a copy of. Ordinary callers wrap an array and never
            // reach this, and the copy is of what remains rather than of the
            // envelope, because how long the envelope is cannot be known
            // until it has been read.
            byte[] remaining = new byte[buffer.remaining()];
            ByteBuffer view = buffer.duplicate();
            view.get(remaining);
            result = OwidReader.read(remaining, 0, remaining.length, true);
        }
        // The buffer moves on by exactly what the read occupied, which is the
        // envelope for a success, the single byte for an absent node, and
        // nothing at all for a failure. A failed read therefore leaves the
        // buffer at the start of the frame that failed.
        //
        // Buffer.position is called rather than ByteBuffer.position because
        // the covariant override arrived in Java 9 and this library is built
        // for 8.
        ((Buffer) buffer).position(buffer.position() + result.getByteCount());
        return result;
    }

    /**
     * Returns the OWID as a byte array including the signature.
     *
     * @return the serialized bytes
     * @throws OwidException if the OWID has not been signed, or a field cannot
     *                       be encoded
     */
    public byte[] asByteArray() throws OwidException {
        ExactByteArrayOutputStream buffer =
                new ExactByteArrayOutputStream(byteCount(true));
        toBuffer(buffer);
        return buffer.toExactByteArray();
    }

    /**
     * Returns the OWID as a base 64 encoded string with padding.
     *
     * @return the base 64 encoded OWID
     * @throws OwidException see {@link #asByteArray()}
     */
    public String asBase64() throws OwidException {
        return Base64.getEncoder().encodeToString(asByteArray());
    }

    /** Appends the OWID, including the signature, to the buffer provided. */
    void toBuffer(ByteArrayOutputStream buffer) throws OwidException {
        writeNoSignature(buffer, version, domain, date, payload);
        Io.writeSignature(buffer, signature);
    }

    /**
     * Writes the marker for an absent optional OWID, being the single byte
     * zero, for embedding in a larger framed byte array.
     *
     * <p>Reading it back reports {@link OwidParseStatus#ABSENT_NODE} and
     * hands back no value, because the marker stands for the absence of an
     * identifier rather than for one, and an OWID with no domain, no date and
     * no signature would be one nothing had ever signed. The first byte
     * settles that on both reading contracts, since nothing after it can
     * turn the value into an OWID. Read as a frame, through
     * {@link #parse(ByteBuffer)}, the marker is consumed, so a caller walking
     * a run of frames steps over the absent node and reads the frame after
     * it.</p>
     *
     * @return a single byte array holding the empty marker
     */
    public static byte[] emptyByteArray() {
        return new byte[] {Version.EMPTY.asByte()};
    }

    /**
     * Appends the fields other than the signature to the buffer. This is the
     * data over which the signature is calculated.
     */
    private static void writeNoSignature(ByteArrayOutputStream buffer,
            Version version, String domain, Instant date, byte[] payload)
            throws OwidException {
        Io.writeByte(buffer, version.asByte());
        Io.writeString(buffer, domain);
        Io.writeDate(buffer, date, version);
        Io.writeByteArray(buffer, payload);
    }

    /**
     * Builds the byte array used for signing and verification. Contains the
     * fields of this OWID without the signature, followed by the complete byte
     * form of each of the others in the order provided.
     */
    byte[] dataForCrypto(List<Owid> others) throws OwidException {
        return dataForCrypto(version, domain, date, payload, others);
    }

    /**
     * The same bytes for fields that are not yet an OWID, which is what the
     * creator holds at the moment it signs. Nothing partly built exists,
     * because the creator keeps loose fields until it has a signature and
     * then builds the finished OWID in one step.
     */
    static byte[] dataForCrypto(Version version, String domain, Instant date,
            byte[] payload, List<Owid> others) throws OwidException {
        int length = byteCount(version, domain, payload, null, false);
        for (Owid other : others) {
            length = addLength(length, other.byteCount(true));
        }
        ExactByteArrayOutputStream buffer =
                new ExactByteArrayOutputStream(length);
        writeNoSignature(buffer, version, domain, date, payload);
        for (Owid other : others) {
            other.toBuffer(buffer);
        }
        return buffer.toExactByteArray();
    }

    /** The exact number of bytes serialization will write. */
    private int byteCount(boolean includeSignature) throws OwidException {
        return byteCount(version, domain, payload, signature,
                includeSignature);
    }

    /**
     * The exact number of bytes serialization will write for the fields
     * given. The signature may be null when it is not being counted.
     */
    private static int byteCount(Version version, String domain,
            byte[] payload, byte[] signature, boolean includeSignature)
            throws OwidException {
        int dateLength;
        switch (version) {
            case VERSION1:
                dateLength = 2;
                break;
            case VERSION2:
            case VERSION3:
                dateLength = 4;
                break;
            default:
                throw new OwidException(
                        "OWID version '" + version + "' not supported");
        }
        int length = 1;
        length = addLength(length,
                domain.getBytes(StandardCharsets.UTF_8).length);
        length = addLength(length, 1);
        length = addLength(length, dateLength);
        length = addLength(length, 4);
        length = addLength(length, payload.length);
        if (includeSignature) {
            if (signature.length != SIGNATURE_LENGTH) {
                throw Io.invalidSignatureLength(signature.length);
            }
            length = addLength(length, SIGNATURE_LENGTH);
        }
        return length;
    }

    /**
     * Adds serialized lengths without allowing signed int overflow to turn
     * an implementation capacity failure into a malformed OWID.
     */
    private static int addLength(int left, int right) throws OwidException {
        if (right < 0 || left > Integer.MAX_VALUE - right) {
            throw new CapacityException(
                    "OWID byte length exceeds Java array capacity");
        }
        return left + right;
    }

    /**
     * A byte stream whose backing array is already the exact final size.
     * Returning that array avoids ByteArrayOutputStream's final full copy.
     */
    private static final class ExactByteArrayOutputStream
            extends ByteArrayOutputStream {

        ExactByteArrayOutputStream(int size) {
            super(size);
        }

        byte[] toExactByteArray() throws OwidException {
            if (count != buf.length) {
                throw new OwidException(
                        "serialized OWID length did not match its fields");
            }
            return buf;
        }
    }

    /**
     * The payload interpreted as a UTF-8 string.
     *
     * @return the payload decoded as UTF-8
     */
    public String payloadAsString() {
        return new String(payload, StandardCharsets.UTF_8);
    }

    /**
     * The payload as lower case hexadecimal for display purposes, with no
     * separators. For example the bytes 0x01 0x03 produce "0103".
     *
     * @return the payload as a hex string
     */
    public String payloadAsPrintable() {
        StringBuilder builder = new StringBuilder(payload.length * 2);
        for (byte b : payload) {
            builder.append(Character.forDigit((b >> 4) & 0xF, 16));
            builder.append(Character.forDigit(b & 0xF, 16));
        }
        return builder.toString();
    }

    /**
     * The payload as a base 64 encoded string with padding.
     *
     * @return the payload as base 64
     */
    public String payloadAsBase64() {
        return Base64.getEncoder().encodeToString(payload);
    }

    /**
     * Returns the number of complete minutes that have elapsed since the OWID
     * was created. The granularity is to the nearest minute.
     *
     * @return the age in minutes
     */
    public long ageMinutes() {
        return Duration.between(date, Instant.now()).toMinutes();
    }

    /**
     * Verifies this OWID, and any others that were included when it was
     * signed, using the crypto instance provided. Pass an empty list for the
     * others when the OWID was signed on its own.
     *
     * @param crypto the crypto instance holding the public key
     * @param others the other OWIDs that were signed together with this one,
     *               in the same order as when signed
     * @return true if the signature verifies, false otherwise
     * @throws OwidException if the crypto instance cannot verify, or a field
     *                       cannot be encoded
     */
    public boolean verifyWithCrypto(Crypto crypto, List<Owid> others)
            throws OwidException {
        byte[] data = dataForCrypto(others);
        return crypto.verifyByteArray(data, signature);
    }

    /**
     * Verifies this OWID, and any others that were included when it was
     * signed, using the public key in SPKI PEM form provided.
     *
     * @param publicPem the public key in SPKI PEM form
     * @param others    the other OWIDs that were signed together with this
     *                  one, in the same order as when signed
     * @return true if the signature verifies, false otherwise
     * @throws OwidException if the PEM is not a valid public key, or a field
     *                       cannot be encoded
     */
    public boolean verifyWithPublicKey(String publicPem, List<Owid> others)
            throws OwidException {
        Crypto crypto = Crypto.newVerifyOnly(publicPem);
        return verifyWithCrypto(crypto, others);
    }

    /**
     * Asks whether the signature is genuine and reports why, keeping "does
     * not match" apart from "could not check".
     *
     * <p>A key that cannot be used leaves the signature unjudged, and saying
     * that it is invalid would report an outage as an attack, so the two
     * arrive as different statuses.</p>
     *
     * @param crypto the crypto instance holding the public key, which may be
     *               null when no key could be obtained
     * @param others the other OWIDs that were signed together with this one,
     *               in the same order as when signed
     * @return the outcome of the check
     */
    public OwidVerificationResult verify(Crypto crypto, List<Owid> others) {
        if (crypto == null || crypto.canVerify() == false) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.KEY_UNAVAILABLE);
        }
        if (signature.length != SIGNATURE_LENGTH) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.INVALID_SIGNATURE_LENGTH);
        }
        byte[] data;
        try {
            data = dataForCrypto(others);
        } catch (CapacityException e) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.IMPLEMENTATION_CAPACITY_EXCEEDED);
        } catch (OwidException e) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.VERIFICATION_ERROR);
        }
        boolean valid;
        try {
            valid = crypto.verifyByteArray(data, signature);
        } catch (OwidException e) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.VERIFICATION_ERROR);
        }
        return OwidVerificationResult.of(valid
                ? OwidSignatureStatus.SIGNATURE_VALID
                : OwidSignatureStatus.SIGNATURE_INVALID);
    }

    /**
     * The same question as {@link #verify(Crypto, List)}, starting from the
     * public key in SPKI PEM form.
     *
     * <p>Key material that cannot be decoded reports
     * {@link OwidSignatureStatus#INVALID_KEY}, because the fault is in the
     * key rather than in the identifier.</p>
     *
     * @param publicPem the public key in SPKI PEM form, which may be null
     *                  when no key could be obtained
     * @param others    the other OWIDs that were signed together with this
     *                  one, in the same order as when signed
     * @return the outcome of the check
     */
    public OwidVerificationResult verify(String publicPem,
            List<Owid> others) {
        if (publicPem == null || publicPem.trim().isEmpty()) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.KEY_UNAVAILABLE);
        }
        Crypto crypto;
        try {
            crypto = Crypto.newVerifyOnly(publicPem);
        } catch (OwidException e) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.INVALID_KEY);
        }
        return verify(crypto, others);
    }

    /**
     * Returns the byte version of the OWID.
     *
     * @return the version
     */
    public Version getVersion() {
        return version;
    }

    /**
     * Returns the domain associated with the creator.
     *
     * @return the domain
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Returns the creation date and time, used to the nearest minute, in UTC.
     *
     * @return the date
     */
    public Instant getDate() {
        return date;
    }

    /**
     * Returns a copy of the payload bytes, so that writing into the array
     * returned cannot alter an OWID whose signature was calculated over the
     * original bytes.
     *
     * @return the payload
     */
    public byte[] getPayload() {
        return payload.clone();
    }

    /**
     * Returns the payload length without copying the payload. This is useful
     * when applying a use-case-specific size policy after parsing.
     *
     * @return the payload length in bytes
     */
    public int getPayloadLength() {
        return payload.length;
    }

    /**
     * Returns a copy of the signature bytes, for the same reason as
     * {@link #getPayload()}.
     *
     * @return the signature
     */
    public byte[] getSignature() {
        return signature.clone();
    }

    /**
     * Formats the OWID as a base 64 string, or the text of the error if it
     * cannot be encoded.
     *
     * @return the base 64 string or the error text
     */
    @Override
    public String toString() {
        try {
            return asBase64();
        } catch (OwidException e) {
            return e.getMessage();
        }
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Owid)) {
            return false;
        }
        Owid that = (Owid) other;
        return version == that.version
                && domain.equals(that.domain)
                && date.equals(that.date)
                && Arrays.equals(payload, that.payload)
                && Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = version.hashCode();
        result = 31 * result + domain.hashCode();
        result = 31 * result + date.hashCode();
        result = 31 * result + Arrays.hashCode(payload);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }
}
