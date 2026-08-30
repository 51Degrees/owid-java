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

/**
 * Low level read and write helpers for the OWID binary format. The format
 * uses little endian unsigned 32 bit integers, null terminated strings, and a
 * fixed 64 byte signature. Version 1 stores the date as a two byte big endian
 * count of hours.
 *
 * <p>The class is not part of the public API. The methods are package private
 * so that the unit tests can exercise them directly.</p>
 */
final class Io {

    /**
     * The base date for OWIDs as a unix timestamp. The date and time
     * information is stored as the number of hours or minutes after
     * 2020-01-01T00:00:00 UTC.
     */
    static final long BASE_DATE_EPOCH_SECONDS = 1_577_836_800L;

    /**
     * The longest domain an OWID can hold, in characters. RFC 1035 section
     * 2.3.4, "Size limits", restricts the total length of a domain name to
     * 255 octets or less, and that limit counts the wire format, which
     * spends one length octet on every label and one zero octet on the
     * root. An OWID stores the presentation form instead, being the text
     * "example.com", where the dots stand in for the label length octets
     * and the root has no text at all, so the same published limit is two
     * characters shorter here.
     */
    static final int MAXIMUM_DOMAIN_LENGTH = 253;

    private Io() {
    }

    /**
     * Returns the base date for OWIDs as an instant.
     *
     * @return 2020-01-01T00:00:00Z
     */
    static Instant baseDate() {
        return Instant.ofEpochSecond(BASE_DATE_EPOCH_SECONDS);
    }

    /** Sequential reader over a byte buffer. */
    static final class Reader {

        private final byte[] buffer;
        private int position;

        Reader(byte[] buffer) {
            this.buffer = buffer;
            this.position = 0;
        }

        int position() {
            return position;
        }

        int readByte() throws OwidException {
            if (position >= buffer.length) {
                throw endOfBuffer();
            }
            return buffer[position++] & 0xFF;
        }

        /**
         * Copies the next count bytes. The end of the buffer is checked
         * before the copy is sized, so a count beyond the bytes present is
         * refused without allocating.
         */
        private byte[] readBytes(int count) throws OwidException {
            if (count < 0) {
                throw new OwidException("payload length is negative");
            }
            long end = (long) position + count;
            if (end > buffer.length) {
                throw endOfBuffer();
            }
            byte[] value = new byte[count];
            System.arraycopy(buffer, position, value, 0, count);
            position += count;
            return value;
        }

        /**
         * Reads the domain, being the bytes up to the null terminator. The
         * search stops at {@link Io#MAXIMUM_DOMAIN_LENGTH} rather than at
         * the end of the buffer, so a buffer whose terminator is missing or
         * corrupted costs no more than the published maximum however long
         * that buffer is, and a domain longer than the maximum is refused
         * without reading past it.
         */
        String readString() throws OwidException {
            long lastTerminator = (long) position + MAXIMUM_DOMAIN_LENGTH;
            int limit = (int) Math.min(buffer.length - 1L, lastTerminator);
            int terminator = -1;
            for (int i = position; i <= limit; i++) {
                if (buffer[i] == 0) {
                    terminator = i;
                    break;
                }
            }
            if (terminator < 0) {
                if (lastTerminator < buffer.length) {
                    throw domainTooLong();
                }
                throw endOfBuffer();
            }
            String value = new String(buffer, position, terminator - position,
                    StandardCharsets.UTF_8);
            position = terminator + 1;
            return value;
        }

        /** Reads an unsigned 32 bit integer in little endian byte order. */
        long readUInt32() throws OwidException {
            return ((long) readByte())
                    | ((long) readByte() << 8)
                    | ((long) readByte() << 16)
                    | ((long) readByte() << 24);
        }

        /**
         * Reads the length prefixed payload. The count is whatever the sender
         * declared, so it is checked against the bytes actually present
         * before anything is sized by it. A valid OWID is the declared
         * payload followed by the signature and nothing else, so the count
         * must equal the bytes remaining less the signature length, and any
         * other count, short or long, is refused here. The same check refuses
         * an envelope with bytes after the signature, which was previously
         * accepted and ignored, and one whose signature is short.
         */
        byte[] readByteArray() throws OwidException {
            long count = readUInt32();
            long remaining = (long) buffer.length - position;
            long expected = count + Owid.SIGNATURE_LENGTH;
            if (remaining != expected) {
                throw new OwidException("OWID payload length '" + count
                        + "' does not match the '" + remaining
                        + "' bytes present, of which the final '"
                        + Owid.SIGNATURE_LENGTH + "' must be the signature");
            }
            return readBytes((int) count);
        }

        /** Reads the fixed length signature. */
        byte[] readSignature() throws OwidException {
            return readBytes(Owid.SIGNATURE_LENGTH);
        }

        /** Reads the date using the encoding associated with the version. */
        Instant readDate(Version version) throws OwidException {
            switch (version) {
                case VERSION1: {
                    int high = readByte();
                    int low = readByte();
                    long hours = ((long) high << 8) | low;
                    return baseDate().plus(Duration.ofHours(hours));
                }
                case VERSION2:
                case VERSION3: {
                    long minutes = readUInt32();
                    return baseDate().plus(Duration.ofMinutes(minutes));
                }
                default:
                    throw new OwidException("OWID version '"
                            + (version.asByte() & 0xFF) + "' not supported");
            }
        }

        private static OwidException endOfBuffer() {
            return new OwidException("buffer ended before the OWID was complete");
        }
    }

    static void writeByte(ByteArrayOutputStream buffer, byte value) {
        buffer.write(value);
    }

    /**
     * Writes the string followed by the null terminator. The string must not
     * contain a null character as that would conflict with the terminator,
     * and must be no longer than {@link #MAXIMUM_DOMAIN_LENGTH} bytes, being
     * the bound the read applies, so the library cannot write a domain it
     * would then refuse to read back. The count is of the UTF-8 bytes
     * because those are what the read counts as it walks to the terminator.
     */
    static void writeString(ByteArrayOutputStream buffer, String value)
            throws OwidException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAXIMUM_DOMAIN_LENGTH) {
            throw domainTooLong();
        }
        for (byte b : bytes) {
            if (b == 0) {
                throw new OwidException("domain '" + value + "' is not valid");
            }
        }
        buffer.write(bytes, 0, bytes.length);
        buffer.write(0);
    }

    /** Writes an unsigned 32 bit integer in little endian byte order. */
    static void writeUInt32(ByteArrayOutputStream buffer, long value) {
        buffer.write((int) (value & 0xFF));
        buffer.write((int) ((value >> 8) & 0xFF));
        buffer.write((int) ((value >> 16) & 0xFF));
        buffer.write((int) ((value >> 24) & 0xFF));
    }

    /**
     * Writes a byte array prefixed with its length as an unsigned 32 bit
     * integer.
     */
    static void writeByteArray(ByteArrayOutputStream buffer, byte[] value)
            throws OwidException {
        if (value.length > 0xFFFFFFFFL) {
            throw new OwidException("payload length '" + value.length
                    + "' exceeds the unsigned 32 bit limit");
        }
        writeUInt32(buffer, value.length);
        buffer.write(value, 0, value.length);
    }

    /** Writes the fixed length signature, validating the length. */
    static void writeSignature(ByteArrayOutputStream buffer, byte[] value)
            throws OwidException {
        if (value.length != Owid.SIGNATURE_LENGTH) {
            throw invalidSignatureLength(value.length);
        }
        buffer.write(value, 0, value.length);
    }

    /** Writes the date using the encoding associated with the version. */
    static void writeDate(ByteArrayOutputStream buffer, Instant date,
            Version version) throws OwidException {
        switch (version) {
            case VERSION1: {
                long hours = Duration.between(baseDate(), date).toHours();
                if (hours < 0 || hours > 0xFFFFL) {
                    throw dateOutOfRange();
                }
                buffer.write((int) ((hours >> 8) & 0xFF));
                buffer.write((int) (hours & 0xFF));
                break;
            }
            case VERSION2:
            case VERSION3: {
                long minutes = Duration.between(baseDate(), date).toMinutes();
                if (minutes < 0 || minutes > 0xFFFFFFFFL) {
                    throw dateOutOfRange();
                }
                writeUInt32(buffer, minutes);
                break;
            }
            default:
                throw new OwidException("OWID version '"
                        + (version.asByte() & 0xFF) + "' not supported");
        }
    }

    /**
     * The refusal used by both halves of the library when a domain is longer
     * than the published maximum, so the read and the write report the one
     * condition in the same words.
     */
    static OwidException domainTooLong() {
        return new OwidException("domain is longer than the '"
                + MAXIMUM_DOMAIN_LENGTH + "' character maximum");
    }

    static OwidException invalidSignatureLength(int length) {
        return new OwidException("signature length '" + length
                + "' not compatible with '" + Owid.SIGNATURE_LENGTH
                + "' OWID signature length");
    }

    private static OwidException dateOutOfRange() {
        return new OwidException(
                "date can not be stored in the encoding for the OWID version");
    }
}
