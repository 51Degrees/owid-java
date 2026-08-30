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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * OWID structure which can be used as a node in a tree.
 *
 * <p>An OWID records that the processor operating the domain handled the
 * payload, and any other OWIDs covered by the signature, at the date and time
 * given. Once signed it is immutable. Any change to the fields will cause
 * verification to fail.</p>
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

    private Version version;
    private String domain;
    private Instant date;
    private byte[] payload;
    private byte[] signature;

    /**
     * Creates an empty unsigned OWID with the current version, an empty
     * domain, the current date truncated to the minute, an empty payload, and
     * no signature.
     */
    public Owid() {
        this.version = Version.current();
        this.domain = "";
        this.date = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        this.payload = new byte[0];
        this.signature = new byte[0];
    }

    /**
     * Creates a new unsigned OWID with the domain, date, and payload provided
     * and the current version.
     *
     * @param domain  the domain associated with the creator
     * @param date    the creation date, used to the minute
     * @param payload the payload bytes
     */
    public Owid(String domain, Instant date, byte[] payload) {
        this.version = Version.current();
        this.domain = domain;
        this.date = date;
        this.payload = payload.clone();
        this.signature = new byte[0];
    }

    /**
     * Creates an OWID from a base 64 encoded string. Decoding accepts the
     * standard alphabet with or without the trailing padding.
     *
     * @param value the base 64 encoded OWID
     * @return the parsed OWID
     * @throws OwidException if the string is not valid base 64, or the bytes
     *                       are not a valid OWID
     */
    public static Owid fromBase64(String value) throws OwidException {
        return fromByteArray(decodeBase64(value));
    }

    /**
     * Creates an OWID from its binary form.
     *
     * @param buffer the serialized OWID bytes
     * @return the parsed OWID
     * @throws OwidException if the first byte is not a known version, the
     *                       buffer is too short for the remaining fields, the
     *                       domain is unterminated or longer than the maximum
     *                       published for a domain name, or the declared
     *                       payload length does not leave exactly the 64 byte
     *                       signature at the end
     */
    public static Owid fromByteArray(byte[] buffer) throws OwidException {
        return fromReader(new Io.Reader(buffer));
    }

    /** Creates an OWID by reading the next fields from the reader. */
    static Owid fromReader(Io.Reader reader) throws OwidException {
        Version version = Version.fromByte(reader.readByte());
        Owid owid = new Owid();
        owid.version = version;
        if (version == Version.EMPTY) {
            owid.domain = "";
            owid.payload = new byte[0];
            owid.signature = new byte[0];
            return owid;
        }
        owid.domain = reader.readString();
        owid.date = reader.readDate(version);
        owid.payload = reader.readByteArray();
        owid.signature = reader.readSignature();
        return owid;
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
        toBufferNoSignature(buffer);
        Io.writeSignature(buffer, signature);
    }

    /**
     * Writes an empty OWID marker. Used to indicate optional OWIDs in byte
     * arrays.
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
    void toBufferNoSignature(ByteArrayOutputStream buffer) throws OwidException {
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
        int length = byteCount(false);
        for (Owid other : others) {
            length = addLength(length, other.byteCount(true));
        }
        ExactByteArrayOutputStream buffer =
                new ExactByteArrayOutputStream(length);
        toBufferNoSignature(buffer);
        for (Owid other : others) {
            other.toBuffer(buffer);
        }
        return buffer.toExactByteArray();
    }

    /**
     * The exact number of bytes serialization will write.
     */
    private int byteCount(boolean includeSignature) throws OwidException {
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
            throw new OwidException(
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
     * Returns the byte version of the OWID.
     *
     * @return the version
     */
    public Version getVersion() {
        return version;
    }

    /**
     * Sets the byte version of the OWID.
     *
     * @param version the version
     */
    public void setVersion(Version version) {
        this.version = version;
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
     * Sets the domain associated with the creator.
     *
     * @param domain the domain
     */
    public void setDomain(String domain) {
        this.domain = domain;
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
     * Sets the creation date and time. The serialized form uses the minute
     * truncated value.
     *
     * @param date the date
     */
    public void setDate(Instant date) {
        this.date = date;
    }

    /**
     * Returns a copy of the payload bytes.
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
     * Sets the payload bytes.
     *
     * @param payload the payload
     */
    public void setPayload(byte[] payload) {
        this.payload = payload.clone();
    }

    /**
     * Returns a copy of the signature bytes.
     *
     * @return the signature
     */
    public byte[] getSignature() {
        return signature.clone();
    }

    /**
     * Sets the signature bytes.
     *
     * @param signature the signature
     */
    void setSignature(byte[] signature) {
        this.signature = signature.clone();
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

    /** Decodes base 64 accepting input with or without trailing padding. */
    private static byte[] decodeBase64(String value) throws OwidException {
        try {
            return Base64.getMimeDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new OwidException("base 64 decoding failed because "
                    + e.getMessage(), e);
        }
    }
}
