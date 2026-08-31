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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

/**
 * The payload length field of an OWID is whatever the sender declared, so
 * parsing must check it against the bytes present before sizing anything by
 * it. These tests prove that a declared length that does not leave exactly
 * the signature after the payload is refused, that refusing it costs no
 * allocation sized by the declared number, and that a correctly sized
 * envelope still parses. The 64 byte signature is the fixed tail every valid
 * OWID ends with.
 */
class PayloadLengthTest {

    private static final int SIGNATURE_LENGTH = Owid.SIGNATURE_LENGTH;

    private static final String DOMAIN = "51d.es";

    private static final byte[] PAYLOAD = filled(37, (byte) 0x5A);

    private static final byte[] SIGNATURE =
            filled(SIGNATURE_LENGTH, (byte) 0x99);

    /** The refusal of any declared length must allocate under this. */
    private static final long ALLOCATION_BOUND = 64L * 1024;

    /**
     * A version 3 envelope, being the version byte, the domain with its
     * terminator, four minute bytes, the declared payload length, the
     * payload bytes given and the signature bytes given, so a test can make
     * the declared length and the bytes present disagree. The bytes are
     * written by hand rather than through the library so the test does not
     * depend on the writer it is checking the reader against.
     */
    private static byte[] envelope(
            long declaredLength, byte[] payload, byte[] signature) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(Version.VERSION3.asByte());
        byte[] domain = DOMAIN.getBytes(StandardCharsets.US_ASCII);
        stream.write(domain, 0, domain.length);
        stream.write(0);
        writeLittleEndian(stream, 1000L);
        writeLittleEndian(stream, declaredLength);
        stream.write(payload, 0, payload.length);
        stream.write(signature, 0, signature.length);
        return stream.toByteArray();
    }

    private static void writeLittleEndian(
            ByteArrayOutputStream stream, long value) {
        stream.write((int) (value & 0xFF));
        stream.write((int) ((value >> 8) & 0xFF));
        stream.write((int) ((value >> 16) & 0xFF));
        stream.write((int) ((value >> 24) & 0xFF));
    }

    private static byte[] filled(int length, byte value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }

    /**
     * Bytes allocated so far on the current thread, from the HotSpot thread
     * bean. The test fails rather than passing silently if the runtime
     * cannot measure allocation, because the allocation bound is the point
     * of the test that calls this.
     */
    private static long allocatedBytes() {
        ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        assertTrue(bean instanceof com.sun.management.ThreadMXBean,
                "the runtime must be able to measure thread allocation");
        com.sun.management.ThreadMXBean sun =
                (com.sun.management.ThreadMXBean) bean;
        assertTrue(sun.isThreadAllocatedMemoryEnabled(),
                "thread allocation measurement must be enabled");
        return sun.getThreadAllocatedBytes(Thread.currentThread().getId());
    }

    /**
     * The declared length matches the bytes present, the signature is the
     * last 64 bytes, and the envelope parses to the same payload.
     */
    @Test
    void declaredLengthMatchesParses() {
        Owid owid = ParseAssert.parsed(Owid.parse(
                envelope(PAYLOAD.length, PAYLOAD, SIGNATURE)));
        assertArrayEquals(PAYLOAD, owid.getPayload(),
                "should read the payload back unchanged");
        assertArrayEquals(SIGNATURE, owid.getSignature(),
                "should read the signature back unchanged");
        assertEquals(DOMAIN, owid.getDomain(), "should read the domain");
    }

    /**
     * A payload materially larger than an ordinary identifier remains valid
     * when its declaration and bytes agree. Size policy belongs to the
     * application rather than format parsing.
     */
    @Test
    void matchingOneMebibytePayloadParses() {
        byte[] payload = filled(1024 * 1024, (byte) 0x5A);

        Owid owid = ParseAssert.parsed(Owid.parse(
                envelope(payload.length, payload, SIGNATURE)));

        assertEquals(payload.length, owid.getPayloadLength());
        assertArrayEquals(payload, owid.getPayload());
    }

    /**
     * An OWID signed through the library's own creator still parses from
     * its own serialised bytes, so the check agrees with what the library
     * itself produces.
     */
    @Test
    void libraryOutputParses() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create(DOMAIN, crypto);
        Owid original = creator.createBytes(PAYLOAD);
        Owid parsed = ParseAssert.parsed(
                Owid.parse(original.asByteArray()));
        assertArrayEquals(PAYLOAD, parsed.getPayload(),
                "should read the payload the library wrote");
        assertEquals(original, parsed, "should parse to an equal OWID");
        assertTrue(parsed.verifyWithCrypto(crypto, Collections.emptyList()),
                "the parsed OWID should still verify");
    }

    /**
     * One more or one fewer than the bytes present is refused, because
     * either leaves something other than exactly the signature at the end.
     */
    @Test
    void declaredLengthOffByOneRefused() {
        int[] declaredLengths = {PAYLOAD.length - 1, PAYLOAD.length + 1};
        for (int declared : declaredLengths) {
            byte[] bytes = envelope(declared, PAYLOAD, SIGNATURE);
            ParseAssert.failed(Owid.parse(bytes),
                    OwidParseStatus.BYTE_COUNT_MISMATCH);
        }
    }

    /**
     * A byte after the signature is refused, because the signature must be
     * the end of the envelope. Before the check this byte was ignored.
     */
    @Test
    void trailingByteAfterSignatureRefused() {
        byte[] bytes = envelope(PAYLOAD.length, PAYLOAD, SIGNATURE);
        byte[] longer = Arrays.copyOf(bytes, bytes.length + 1);
        ParseAssert.failed(Owid.parse(longer),
                OwidParseStatus.BYTE_COUNT_MISMATCH);
    }

    /**
     * A short signature is refused as a byte count disagreement. The declared
     * payload length is right for the payload, but the bytes after it are
     * fewer than a signature, and what the reader can say for certain is that
     * the declared payload cannot leave exactly the 64 bytes the version
     * requires.
     */
    @Test
    void shortSignatureRefused() {
        byte[] bytes = envelope(PAYLOAD.length, PAYLOAD,
                filled(SIGNATURE_LENGTH - 1, (byte) 0x99));
        ParseAssert.failed(Owid.parse(bytes),
                OwidParseStatus.BYTE_COUNT_MISMATCH);
    }

    /**
     * A large declaration whose payload bytes are absent is refused without
     * an allocation sized by the declared number. The envelope is a few
     * dozen bytes while declaring 64 MiB, then 2 GiB, then the largest
     * unsigned 32 bit value, and each parse allocates under 64 KiB. The
     * numeric values remain valid when the matching payload is present.
     * Measuring the bytes allocated on this thread proves the refusal
     * happened before any array was sized from the declaration.
     */
    @Test
    void mismatchedLargeDeclarationRefusedWithoutAllocating() {
        long[] declaredLengths = {
            64L * 1024 * 1024,
            0x7FFFFFFFL,
            0xFFFFFFFFL,
        };
        for (long declared : declaredLengths) {
            byte[] bytes = envelope(declared, new byte[0], new byte[0]);
            long before = allocatedBytes();
            OwidParseResult result = Owid.parse(bytes);
            long allocated = allocatedBytes() - before;
            ParseAssert.failed(result, OwidParseStatus.BYTE_COUNT_MISMATCH);
            assertTrue(allocated < ALLOCATION_BOUND, "declared " + declared
                    + " allocated " + allocated + " bytes");

            // The framed read is handed the same claim, since it sizes the
            // payload from the declaration too and a sender picks the number
            // there as well.
            ByteBuffer framed = ByteBuffer.wrap(bytes);
            before = allocatedBytes();
            OwidParseResult framedResult = Owid.parse(framed);
            allocated = allocatedBytes() - before;
            ParseAssert.failed(framedResult, OwidParseStatus.UNEXPECTED_END);
            assertTrue(allocated < ALLOCATION_BOUND, "framed declared "
                    + declared + " allocated " + allocated + " bytes");
            assertEquals(0, framed.position(),
                    "a refused frame should consume nothing");
        }
    }

    /**
     * A declared length of zero with nothing but the signature after it
     * parses to an empty payload, so the check does not refuse the smallest
     * valid envelope.
     */
    @Test
    void emptyPayloadParses() {
        Owid owid = ParseAssert.parsed(
                Owid.parse(envelope(0, new byte[0], SIGNATURE)));
        assertEquals(0, owid.getPayload().length,
                "should read an empty payload");
        assertArrayEquals(SIGNATURE, owid.getSignature(),
                "should read the signature after the empty payload");
    }
}
