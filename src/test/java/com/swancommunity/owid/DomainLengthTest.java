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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

/**
 * An OWID stores the creator domain as text followed by a zero terminator,
 * and parsing finds the end of the domain by walking forward to that
 * terminator. A missing or corrupted terminator once made the walk run to the
 * end of the buffer, which is work whose size an attacker chooses. RFC 1035
 * section 2.3.4 publishes a maximum for a domain name, so these tests prove
 * that a domain at that maximum still parses, that a longer one is refused,
 * that a buffer with no terminator at all is refused, and that refusing a
 * hostile buffer costs no more than the maximum however long the buffer is.
 *
 * <p>The same maximum binds the write, because a library that can emit an
 * OWID it cannot read leaves the fault to surface at the consumer rather
 * than at the creator. The later tests prove a creator refuses a domain over
 * the maximum when the caller supplies it, before the private key is used at
 * all, and that serialising refuses a domain that arrived by any other
 * route.</p>
 */
class DomainLengthTest {

    private static final int MAXIMUM = Io.MAXIMUM_DOMAIN_LENGTH;

    private static final byte[] PAYLOAD = filled(37, (byte) 0x5A);

    private static final byte[] SIGNATURE =
            filled(Owid.SIGNATURE_LENGTH, (byte) 0x99);

    /** The refusal of any domain field must allocate under this. */
    private static final long ALLOCATION_BOUND = 64L * 1024;

    /**
     * A domain field long enough that walking it would show plainly in the
     * allocation figure, being far more than the published maximum.
     */
    private static final int HOSTILE_DOMAIN_LENGTH = 16 * 1024 * 1024;

    /**
     * A version 3 envelope carrying the domain bytes given, being the version
     * byte, those bytes with a terminator after them, four minute bytes, the
     * payload with its declared length, and the signature. The bytes are
     * written by hand rather than through the library so the test does not
     * depend on the writer it is checking the reader against.
     */
    private static byte[] envelope(byte[] domain) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(Version.VERSION3.asByte());
        stream.write(domain, 0, domain.length);
        stream.write(0);
        writeLittleEndian(stream, 1000L);
        writeLittleEndian(stream, PAYLOAD.length);
        stream.write(PAYLOAD, 0, PAYLOAD.length);
        stream.write(SIGNATURE, 0, SIGNATURE.length);
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
     * A domain of the length given, written as labels separated by dots so it
     * has the shape of a real name rather than one long run of letters.
     */
    private static String domainOfLength(int length) {
        StringBuilder builder = new StringBuilder(length);
        while (builder.length() < length) {
            builder.append(builder.length() % 64 == 63 ? '.' : 'a');
        }
        return builder.toString();
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Bytes allocated so far on the current thread, from the HotSpot thread
     * bean. The test fails rather than passing silently if the runtime cannot
     * measure allocation, because the allocation bound is the point of the
     * test that calls this.
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
     * A domain of exactly the published maximum parses, keeps its value, and
     * survives being written back out and read again.
     */
    @Test
    void maximumLengthDomainParses() throws OwidException {
        String domain = domainOfLength(MAXIMUM);
        byte[] bytes = envelope(ascii(domain));

        Owid owid = ParseAssert.parsed(Owid.parse(bytes));

        assertEquals(MAXIMUM, owid.getDomain().length(),
                "should read a domain of the published maximum length");
        assertEquals(domain, owid.getDomain(), "should read the domain");
        assertArrayEquals(PAYLOAD, owid.getPayload(),
                "should read the payload that follows the domain");
        assertArrayEquals(bytes, owid.asByteArray(),
                "should write the same bytes back out");
        assertEquals(owid,
                ParseAssert.parsed(Owid.parse(owid.asByteArray())),
                "should parse its own output to an equal OWID");
    }

    /**
     * One character more than the published maximum is refused, even though
     * the terminator and every field after it are present and correct.
     */
    @Test
    void overMaximumLengthDomainRefused() {
        byte[] bytes = envelope(ascii(domainOfLength(MAXIMUM + 1)));

        ParseAssert.failed(Owid.parse(bytes),
                OwidParseStatus.INVALID_DOMAIN_ENCODING);
    }

    /**
     * A buffer whose domain field has no terminator anywhere is refused. The
     * buffer holds nothing but the version byte and letters, so there is no
     * zero for the walk to stop at.
     */
    @Test
    void missingTerminatorRefused() {
        byte[] bytes = filled(64 * 1024, (byte) 'a');
        bytes[0] = Version.VERSION3.asByte();

        ParseAssert.failed(Owid.parse(bytes),
                OwidParseStatus.INVALID_DOMAIN_ENCODING);
    }

    /**
     * A domain field of sixteen mebibytes, terminated far past the maximum,
     * is refused without an allocation sized by the field. Measuring the
     * bytes allocated on this thread proves the cost of the refusal is set by
     * the published maximum and not by the length of the buffer, because
     * building the string the field describes could not fit under the bound.
     */
    @Test
    void hostileDomainRefusedWithoutAllocating() {
        byte[] bytes = envelope(filled(HOSTILE_DOMAIN_LENGTH, (byte) 'a'));

        long before = allocatedBytes();
        OwidParseResult result = Owid.parse(bytes);
        long allocated = allocatedBytes() - before;
        ParseAssert.failed(result, OwidParseStatus.INVALID_DOMAIN_ENCODING);

        assertTrue(allocated < ALLOCATION_BOUND, "refusing a "
                + HOSTILE_DOMAIN_LENGTH + " byte domain field allocated "
                + allocated + " bytes");
    }

    /**
     * A creator holding a domain of exactly the published maximum signs an
     * OWID that serialises, parses back to the same domain, and verifies, so
     * the write bound refuses nothing the library accepted before.
     */
    @Test
    void maximumLengthDomainWritten() throws OwidException {
        String domain = domainOfLength(MAXIMUM);
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create(domain, crypto);

        Owid signed = creator.createBytes(PAYLOAD);
        Owid parsed = ParseAssert.parsed(
                Owid.parse(signed.asByteArray()));

        assertEquals(MAXIMUM, parsed.getDomain().length(),
                "should write and read a domain of the published maximum");
        assertEquals(domain, parsed.getDomain(),
                "should round trip the domain the creator holds");
        assertEquals(signed, parsed, "should parse to an equal OWID");
        assertTrue(parsed.verifyWithCrypto(crypto, Collections.emptyList()),
                "the parsed OWID should still verify");
    }

    /**
     * A creator is refused one character over the maximum, at the point the
     * caller supplies the domain, and the message names the maximum so the
     * caller can see what the domain has to fit.
     */
    @Test
    void overMaximumLengthDomainRefusedByCreator() throws OwidException {
        Crypto crypto = Crypto.generate();

        OwidException thrown = assertThrows(OwidException.class,
                () -> Creator.create(domainOfLength(MAXIMUM + 1), crypto),
                "should refuse a domain one character over the maximum");

        assertNamesMaximum(thrown);
    }

    /**
     * The refusal comes before anything is signed. A creator cannot be built
     * with an over long domain even when the crypto instance holds no private
     * key at all, so the private key is never reached.
     */
    @Test
    void overMaximumLengthDomainRefusedBeforeSigning() throws OwidException {
        String domain = domainOfLength(MAXIMUM + 1);
        Crypto verifyOnly =
                Crypto.newVerifyOnly(Crypto.generate().publicKeyPem());
        assertFalse(verifyOnly.canSign(),
                "the crypto instance should not be able to sign");

        OwidException fromCreator = assertThrows(OwidException.class,
                () -> Creator.create(domain, verifyOnly),
                "should refuse the domain without reaching the crypto");
        assertNamesMaximum(fromCreator);
    }

    /**
     * Assembling the bytes that would be signed refuses a domain over the
     * maximum however it arrived. Only the library itself can reach this,
     * because a caller cannot build an OWID with a domain of its own
     * choosing, so the test asks the library directly.
     */
    @Test
    void overMaximumLengthDomainRefusedWhenAssemblingDataToSign() {
        String domain = domainOfLength(MAXIMUM + 1);

        OwidException thrown = assertThrows(OwidException.class,
                () -> Owid.dataForCrypto(Version.current(), domain,
                        Io.baseDate(), PAYLOAD,
                        Collections.<Owid>emptyList()),
                "should refuse to assemble the bytes that would be signed");

        assertNamesMaximum(thrown);
    }

    /**
     * Serialising refuses a domain over the maximum however it arrived. The
     * OWID here carries a signature of the right length, so the refusal is
     * the domain and not a missing signature.
     */
    @Test
    void overMaximumLengthDomainRefusedWhenSerialising() {
        Owid owid = new Owid(Version.current(), domainOfLength(MAXIMUM + 1),
                Io.baseDate(), PAYLOAD, SIGNATURE);

        OwidException thrown = assertThrows(OwidException.class,
                owid::asByteArray,
                "should refuse to serialise a domain over the maximum");

        assertNamesMaximum(thrown);
    }

    /** The refusal has to name the maximum the caller must fit within. */
    private static void assertNamesMaximum(OwidException thrown) {
        assertTrue(thrown.getMessage().contains(String.valueOf(MAXIMUM)),
                "the message '" + thrown.getMessage()
                        + "' should name the '" + MAXIMUM + "' maximum");
    }

    /**
     * An OWID signed through the library's own creator still parses from its
     * own serialised bytes and still verifies, so the bound is not
     * retrospective on anything the library produces.
     */
    @Test
    void libraryOutputParses() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("51d.es", crypto);
        Owid original = creator.createBytes(PAYLOAD);

        Owid parsed = ParseAssert.parsed(
                Owid.parse(original.asByteArray()));

        assertEquals("51d.es", parsed.getDomain(),
                "should read the domain the library wrote");
        assertEquals(original, parsed, "should parse to an equal OWID");
        assertTrue(parsed.verifyWithCrypto(crypto, Collections.emptyList()),
                "the parsed OWID should still verify");
    }
}
