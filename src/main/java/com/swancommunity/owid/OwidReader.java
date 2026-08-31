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

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

/**
 * Reads a complete OWID from a buffer, reporting why rather than throwing
 * when the bytes are not one.
 *
 * <p>The buffer is walked by index and every read is checked against what is
 * left, so a malformed envelope is a comparison that fails rather than an
 * exception that unwinds. That matters because the data comes from outside,
 * where whoever is sending it chooses how often the read fails and how large
 * each attempt is, and an exception for every attempt is a cost they
 * choose.</p>
 *
 * <p>Nothing here calls the throwing code and catches it. The exception
 * would still be built and unwound, so the cost would remain and only the
 * surface would look different.</p>
 *
 * <p>The same walk serves both reading contracts, which differ in one place
 * only. A whole buffer holds one envelope and nothing else, so the declared
 * payload has to leave exactly the signature at the end and a byte after it
 * belongs to no field. A frame is one envelope inside something longer, so
 * the declared payload and the signature only have to be present, and what
 * follows is the next frame rather than rubbish.</p>
 */
final class OwidReader {

    private OwidReader() {
    }

    /**
     * Reads one OWID from the region of the buffer between the two offsets.
     *
     * @param framed false when the region holds one envelope and nothing
     *               else, so the envelope has to end where the region does,
     *               and true when the envelope is one frame inside something
     *               longer and whatever follows is the next frame
     */
    static OwidParseResult read(byte[] buffer, int from, int total,
            boolean framed) {
        // Nothing supplied is not the same as data that stopped part way
        // through a field, so a region with no bytes in it is reported as the
        // absence it is rather than as a truncation.
        if (buffer == null || total - from <= 0) {
            return OwidParseResult.failed(OwidParseStatus.MISSING_INPUT);
        }

        Version version = Version.forByte(buffer[from] & 0xFF);
        if (version == Version.EMPTY) {
            // The marker for an absent node, being the single byte zero. It
            // is not an OWID and no value is handed back, because it carries
            // no domain, no date and no signature and returning one would put
            // an OWID in a caller's hands that nothing had ever signed. It is
            // not a fault either, since version zero is supported and it
            // means a node is missing, which is why the caller is told that
            // rather than told the version is unknown.
            //
            // The first byte settles this on both contracts, because nothing
            // after it can turn the value into an OWID, so a whole buffer
            // that begins with the marker is reported as an absent node
            // whatever else it carries. Reading a frame the marker is also
            // consumed, so a caller walking a run of frames steps over the
            // absent node and reads the one after it.
            return OwidParseResult.absentNode(1);
        }
        if (version == null) {
            // A version byte this implementation does not know, which is a
            // different thing from the marker above, where the version is
            // known and says a node is missing.
            return OwidParseResult.failed(
                    OwidParseStatus.UNSUPPORTED_VERSION);
        }
        int at = from + 1;

        // The domain, terminated by a zero byte and no longer than the
        // maximum published for a domain name. The walk stops at that
        // maximum rather than at the end of the buffer, so a buffer whose
        // terminator is missing costs no more than the maximum however long
        // that buffer is.
        int start = at;
        int limit = Math.min(total, start + Io.MAXIMUM_DOMAIN_LENGTH + 1);
        String domain = null;
        while (at < limit) {
            if (buffer[at] == 0) {
                domain = new String(buffer, start, at - start,
                        StandardCharsets.UTF_8);
                at++;
                break;
            }
            at++;
        }
        if (domain == null) {
            // Either the buffer ended inside the domain, or the domain ran
            // past the maximum without terminating. The second is a domain
            // that cannot be valid rather than data that merely stopped, so
            // the two are reported differently.
            if (at >= total && at - start <= Io.MAXIMUM_DOMAIN_LENGTH) {
                return OwidParseResult.failed(
                        OwidParseStatus.UNEXPECTED_END);
            }
            return OwidParseResult.failed(
                    OwidParseStatus.INVALID_DOMAIN_ENCODING);
        }

        // The date, whose width depends on the version.
        Instant date;
        if (version == Version.VERSION1) {
            if (total - at < 2) {
                return OwidParseResult.failed(
                        OwidParseStatus.UNEXPECTED_END);
            }
            long hours = ((long) (buffer[at] & 0xFF) << 8)
                    | (buffer[at + 1] & 0xFF);
            at += 2;
            date = Io.baseDate().plus(Duration.ofHours(hours));
        } else {
            if (total - at < 4) {
                return OwidParseResult.failed(
                        OwidParseStatus.UNEXPECTED_END);
            }
            long minutes = readUInt32(buffer, at);
            at += 4;
            date = Io.baseDate().plus(Duration.ofMinutes(minutes));
        }

        if (total - at < 4) {
            return OwidParseResult.failed(OwidParseStatus.UNEXPECTED_END);
        }
        long declared = readUInt32(buffer, at);
        at += 4;

        // The declaration is the sender's claim about a payload not yet
        // read, so it is compared with what is actually present before
        // anything is sized by it. The subtraction is done in a long, and
        // the declaration is read as unsigned into a long, so a buffer with
        // fewer bytes left than a signature needs gives a negative count
        // rather than wrapping, and a negative count can never equal a
        // declaration.
        //
        // Reading a whole buffer, the disagreement is the finding even when
        // the buffer also stopped early. What a reader can say for certain is
        // that the declared payload cannot leave exactly the signature the
        // version requires, and that is true whichever way the bytes fall
        // short. Reporting it as a truncation instead would name a different
        // fault for the same evidence.
        //
        // Reading a frame, only a shortfall is a finding, since a longer
        // input is the next frame rather than a disagreement. A frame that
        // runs past what is here is reported as a truncation, because a
        // caller walking a stream needs to know whether to wait for more
        // bytes or to give up on these, and those are different answers.
        long present = (long) (total - at) - Owid.SIGNATURE_LENGTH;
        if (framed) {
            if (present < declared) {
                return OwidParseResult.failed(
                        OwidParseStatus.UNEXPECTED_END);
            }
        } else if (present != declared) {
            return OwidParseResult.failed(
                    OwidParseStatus.BYTE_COUNT_MISMATCH);
        }

        // The bytes are all here. Whether this runtime can hold them in one
        // array is a separate question with a different answer, because the
        // same envelope may be readable elsewhere. A Java byte array cannot
        // exceed Integer.MAX_VALUE, so neither contract above can be
        // satisfied by a larger declaration and this cannot fire today. It is
        // kept so a future change to that arithmetic cannot silently truncate
        // the cast below.
        if (declared > Integer.MAX_VALUE) {
            return OwidParseResult.failed(
                    OwidParseStatus.IMPLEMENTATION_CAPACITY_EXCEEDED);
        }

        int payloadLength = (int) declared;
        byte[] payload = new byte[payloadLength];
        System.arraycopy(buffer, at, payload, 0, payloadLength);
        at += payloadLength;

        byte[] signature = new byte[Owid.SIGNATURE_LENGTH];
        System.arraycopy(buffer, at, signature, 0, Owid.SIGNATURE_LENGTH);
        at += Owid.SIGNATURE_LENGTH;

        if (framed == false && at != total) {
            // Unreachable while the count check above holds, and kept so
            // that a future change to that arithmetic cannot silently start
            // accepting bytes after the signature. A frame says nothing about
            // what follows it, so the check does not apply there.
            return OwidParseResult.failed(
                    OwidParseStatus.MALFORMED_ENVELOPE);
        }

        return OwidParseResult.parsed(
                new Owid(version, domain, date, payload, signature),
                at - from);
    }

    /**
     * Decodes base 64 without throwing, returning null when the string is not
     * base 64.
     *
     * <p>Written out here rather than handed to {@code java.util.Base64}
     * because neither JDK decoder answers the question this surface has to
     * ask. The strict decoder throws, which is the cost this change exists to
     * remove, and the MIME decoder silently drops every character outside the
     * alphabet, so a string of nothing but rubbish would come back as an
     * empty array and be reported as a missing OWID rather than as text that
     * is not base 64 at all.</p>
     *
     * <p>The standard alphabet is accepted with or without the trailing
     * padding, because both are ordinary ways to carry an encoded OWID.
     * Spaces, tabs and line breaks are skipped, since wrapped encodings are
     * common and were accepted before. Anything else is refused.</p>
     */
    static byte[] decodeBase64(String value) {
        int length = value.length();
        int significant = 0;
        int padding = 0;
        for (int i = 0; i < length; i++) {
            char c = value.charAt(i);
            if (isSkipped(c)) {
                continue;
            }
            if (c == '=') {
                padding++;
                continue;
            }
            if (padding > 0 || c > 127 || DECODE[c] < 0) {
                // Either a character outside the alphabet, or data after the
                // padding that closes the last block.
                return null;
            }
            significant++;
        }

        // Padding only ever brings the final block up to four characters, so
        // any other amount of it means the string was not produced by an
        // encoder.
        int remainder = significant % 4;
        if (remainder == 1) {
            return null;
        }
        if (padding > 0 && padding != (4 - remainder) % 4) {
            return null;
        }

        byte[] decoded = new byte[significant * 3 / 4];
        int bits = 0;
        int held = 0;
        int at = 0;
        for (int i = 0; i < length; i++) {
            char c = value.charAt(i);
            if (c == '=' || isSkipped(c)) {
                continue;
            }
            bits = (bits << 6) | DECODE[c];
            held++;
            if (held == 4) {
                decoded[at++] = (byte) (bits >> 16);
                decoded[at++] = (byte) (bits >> 8);
                decoded[at++] = (byte) bits;
                bits = 0;
                held = 0;
            }
        }
        if (held == 2) {
            decoded[at] = (byte) (bits >> 4);
        } else if (held == 3) {
            decoded[at++] = (byte) (bits >> 10);
            decoded[at] = (byte) (bits >> 2);
        }
        return decoded;
    }

    /** Layout whitespace, which an encoder may have used to wrap lines. */
    private static boolean isSkipped(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    /**
     * The value of each standard alphabet character, and -1 for every other
     * character below 128.
     */
    private static final int[] DECODE = buildDecodeTable();

    private static int[] buildDecodeTable() {
        int[] table = new int[128];
        for (int i = 0; i < table.length; i++) {
            table[i] = -1;
        }
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < alphabet.length(); i++) {
            table[alphabet.charAt(i)] = i;
        }
        return table;
    }

    /**
     * The four bytes at the offset as a little endian unsigned 32 bit value
     * widened into a long, so the full wire range is compared without a
     * signed int wrapping into a negative number.
     */
    private static long readUInt32(byte[] buffer, int offset) {
        return ((long) (buffer[offset] & 0xFF))
                | ((long) (buffer[offset + 1] & 0xFF) << 8)
                | ((long) (buffer[offset + 2] & 0xFF) << 16)
                | ((long) (buffer[offset + 3] & 0xFF) << 24);
    }
}
