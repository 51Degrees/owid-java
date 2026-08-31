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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * The contract the reading surfaces keep for data that arrived from outside.
 *
 * <p>Every read reports three facts, being whether it worked, the OWID only
 * when it did, and a named reason either way, and no expected failure throws.
 * {@link ParseAssert} checks all three on every case here, so a test cannot
 * pass while the result contradicts itself.</p>
 *
 * <p>These are the whole buffer surfaces, being the encoded string and the
 * byte array. The framed surface, which reads one envelope out of something
 * longer, is covered by {@link FramedReadTest}.</p>
 *
 * <p>Every member of {@link OwidParseStatus} is exercised here, with the
 * domain cases also covered in more depth by {@link DomainLengthTest} and the
 * byte count cases by {@link PayloadLengthTest}. Three members are not, and
 * cannot be, being {@link OwidParseStatus#INVALID_INPUT_TYPE}, which the
 * compiler already refuses,
 * {@link OwidParseStatus#IMPLEMENTATION_CAPACITY_EXCEEDED}, which a Java byte
 * array cannot reach on either surface, and
 * {@link OwidParseStatus#MALFORMED_ENVELOPE}, which the byte count rule
 * already makes unreachable and which is kept only as a backstop. The reason
 * is recorded on each of those members as well.</p>
 */
class ParseContractTest {

    /** The bytes of a well formed version 3 envelope with a short payload. */
    private static byte[] wellFormed() {
        return Envelope.version3(new byte[] {1, 2, 3});
    }

    /**
     * A successful read reports all three facts, being success, a value, and
     * the reason PARSED.
     */
    @Test
    void successReportsAllThreeFacts() {
        OwidParseResult result = Owid.parse(wellFormed());

        assertTrue(result.isSuccess(), "should report success");
        assertNotNull(result.getValue(), "should hand back the OWID");
        assertEquals(OwidParseStatus.PARSED, result.getStatus(),
                "should report PARSED");
        assertEquals(Envelope.DOMAIN, result.getValue().getDomain(),
                "should read the fields");
    }

    /** Having nothing to say is allowed, so an empty payload is an OWID. */
    @Test
    void emptyPayloadParses() {
        Owid owid = ParseAssert.parsed(
                Owid.parse(Envelope.version3(new byte[0])));

        assertEquals(0, owid.getPayloadLength(),
                "should read an empty payload");
    }

    /**
     * A one mebibyte payload is an OWID. The limit the format sets is the
     * wire format's, and how much an application accepts is that
     * application's policy rather than the parser's.
     */
    @Test
    void oneMebibytePayloadParsesFromBase64() {
        byte[] payload = Envelope.filled(1024 * 1024, (byte) 0x5A);
        String encoded = Base64.getEncoder().encodeToString(
                Envelope.version3(payload));

        Owid owid = ParseAssert.parsed(Owid.parse(encoded));

        assertEquals(payload.length, owid.getPayloadLength(),
                "should read the whole payload");
        assertArrayEquals(payload, owid.getPayload(),
                "should read the payload unchanged");
    }

    /** Nothing to read is its own answer, on both surfaces. */
    @Test
    void absentInputIsMissingInput() {
        ParseAssert.failed(Owid.parse((String) null),
                OwidParseStatus.MISSING_INPUT);
        ParseAssert.failed(Owid.parse(""), OwidParseStatus.MISSING_INPUT);
        ParseAssert.failed(Owid.parse((byte[]) null),
                OwidParseStatus.MISSING_INPUT);
        ParseAssert.failed(Owid.parse(new byte[0]),
                OwidParseStatus.MISSING_INPUT);
    }

    /**
     * Text that is not base 64 is reported rather than thrown, whether the
     * characters are outside the alphabet, data follows the padding, or the
     * length cannot be a whole number of blocks.
     */
    @Test
    void invalidBase64IsReported() {
        String[] values = {
            "not base 64 at all!",
            "AAAAA*AA",
            "AAAAA",
            "AAAA=AAA",
            "AAA==",
        };
        for (String value : values) {
            OwidParseResult result = assertDoesNotThrow(
                    () -> Owid.parse(value),
                    "should not throw for a value that is not base 64");
            ParseAssert.failed(result, OwidParseStatus.INVALID_BASE64);
        }
    }

    /**
     * Base 64 without the trailing padding is a normal way to carry an
     * encoded OWID, so it is read rather than refused.
     */
    @Test
    void unpaddedBase64IsAccepted() {
        String padded = Base64.getEncoder().encodeToString(wellFormed());
        String unpadded = padded.replace("=", "");

        Owid fromPadded = ParseAssert.parsed(Owid.parse(padded));
        Owid fromUnpadded = ParseAssert.parsed(Owid.parse(unpadded));

        assertEquals(fromPadded, fromUnpadded,
                "padding should make no difference to what is read");
    }

    /** A version byte this implementation does not know is named as such. */
    @Test
    void unknownVersionIsReported() {
        byte[] bytes = wellFormed();
        bytes[0] = 0x04;

        ParseAssert.failed(Owid.parse(bytes),
                OwidParseStatus.UNSUPPORTED_VERSION);
    }

    /**
     * Data that stops inside a field, before the payload length has even been
     * read, is a truncation rather than a byte count disagreement.
     */
    @Test
    void truncatedFieldsAreUnexpectedEnd() {
        byte[] complete = wellFormed();
        int domainEnd = 1 + Envelope.DOMAIN.length() + 1;

        // Inside the domain, with no terminator reached.
        ParseAssert.failed(
                Owid.parse(Arrays.copyOf(complete, domainEnd - 2)),
                OwidParseStatus.UNEXPECTED_END);

        // Inside the date, two of its four bytes present.
        ParseAssert.failed(
                Owid.parse(Arrays.copyOf(complete, domainEnd + 2)),
                OwidParseStatus.UNEXPECTED_END);

        // Inside the payload length field, two of its four bytes present.
        ParseAssert.failed(
                Owid.parse(Arrays.copyOf(complete, domainEnd + 6)),
                OwidParseStatus.UNEXPECTED_END);
    }

    /**
     * A domain that never terminates, or runs past the published maximum
     * before it does, is a domain that cannot be valid rather than data that
     * merely stopped. {@link DomainLengthTest} covers the bound itself and
     * the cost of refusing a hostile field.
     */
    @Test
    void badDomainIsInvalidDomainEncoding() {
        // Terminated, but longer than a domain name is allowed to be.
        StringBuilder tooLong = new StringBuilder();
        while (tooLong.length() <= Io.MAXIMUM_DOMAIN_LENGTH) {
            tooLong.append('a');
        }
        ParseAssert.failed(
                Owid.parse(Envelope.version3(tooLong.toString(), 1000L, 0,
                        new byte[0], Envelope.signature())),
                OwidParseStatus.INVALID_DOMAIN_ENCODING);

        // Never terminated, in a buffer long enough that the walk has to stop
        // itself rather than run out of bytes.
        byte[] unterminated = Envelope.filled(64 * 1024, (byte) 'a');
        unterminated[0] = Version.VERSION3.asByte();
        ParseAssert.failed(Owid.parse(unterminated),
                OwidParseStatus.INVALID_DOMAIN_ENCODING);
    }

    /**
     * A declared payload count that disagrees with the bytes present is
     * refused before anything is sized by it. {@link PayloadLengthTest}
     * covers the counts in every direction and proves nothing is allocated.
     */
    @Test
    void disagreeingByteCountIsByteCountMismatch() {
        byte[] complete = wellFormed();
        byte[] longer = Arrays.copyOf(complete, complete.length + 1);

        ParseAssert.failed(Owid.parse(longer),
                OwidParseStatus.BYTE_COUNT_MISMATCH);
    }

    /**
     * The marker for an absent optional OWID hands back no OWID, which is the
     * thing that matters, and says what it is rather than calling it a fault.
     *
     * <p>It carries no domain, no date and no signature, so handing one back
     * would put an OWID in a caller's hands that nothing had ever signed,
     * which is the state the construction boundary exists to prevent. Version
     * zero is supported and it means something, though, so the caller is told
     * that a node is absent rather than that the version is unknown.</p>
     *
     * <p>The first byte settles this on both reading contracts, because
     * nothing after it can turn the value into an OWID, so a whole buffer
     * beginning with the marker is an absent node whatever else it carries.
     * That is the answer every OWID implementation gives.</p>
     */
    @Test
    void emptyMarkerIsAnAbsentNodeAndNotAnOwid() {
        ParseAssert.absentNode(Owid.parse(Owid.emptyByteArray()));
        ParseAssert.absentNode(Owid.parse("AA=="));

        ParseAssert.absentNode(Owid.parse(new byte[] {0, 1}));
    }

    /**
     * Parsing and verifying are two questions with two answers. An identifier
     * whose bytes are a well formed OWID reads, and only then does asking
     * about the signature report that it does not match.
     */
    @Test
    void structurallyValidWithWrongSignatureParsesThenFailsVerification()
            throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        byte[] bytes = creator.createBytes(new byte[] {1, 2, 3}).asByteArray();

        // A payload byte, so the envelope stays exactly the shape it was and
        // only the signature stops describing the contents.
        bytes[bytes.length - Owid.SIGNATURE_LENGTH - 1] ^= 0x01;

        Owid owid = ParseAssert.parsed(Owid.parse(bytes));

        OwidVerificationResult verification =
                owid.verify(crypto, Collections.<Owid>emptyList());
        assertEquals(OwidSignatureStatus.SIGNATURE_INVALID,
                verification.getStatus(),
                "the signature should be reported as not matching");
        assertFalse(verification.isValid(),
                "a signature that does not match is not valid");
    }

    /**
     * Nothing about a key can happen while a read fails, because neither
     * reading surface is given one. The signatures of both are checked here
     * rather than a call being counted, since a parameter that does not exist
     * cannot be passed a key, and this library retrieves no keys of its own
     * at all.
     */
    @Test
    void readingTakesNoKeyAndNoCrypto() {
        int checked = 0;
        for (Method method : Owid.class.getDeclaredMethods()) {
            if (method.getName().equals("parse") == false) {
                continue;
            }
            checked++;
            for (Class<?> parameter : method.getParameterTypes()) {
                assertTrue(parameter == String.class
                                || parameter == byte[].class
                                || parameter == ByteBuffer.class,
                        "reading should take only the data to read, but "
                                + method.getName() + " takes "
                                + parameter.getName());
            }
        }
        assertEquals(3, checked, "should have checked every read surface");
    }

    /**
     * A run of malformed buffers, none of which throws and none of which
     * hands back a value. The bytes come from a fixed seed so a failure can
     * be reproduced, and half of them are near misses cut or corrupted from a
     * good envelope, so the later checks are reached as well as the first
     * one.
     */
    @Test
    void malformedInputNeverThrows() {
        Random random = new Random(20260830L);
        byte[] complete = wellFormed();

        for (int i = 0; i < 2000; i++) {
            byte[] bytes;
            if (i % 2 == 0) {
                bytes = new byte[random.nextInt(200)];
                random.nextBytes(bytes);
            } else {
                bytes = Arrays.copyOf(complete,
                        random.nextInt(complete.length + 8));
                if (bytes.length > 0) {
                    bytes[random.nextInt(bytes.length)] =
                            (byte) random.nextInt(256);
                }
            }
            byte[] input = bytes;

            OwidParseResult result = assertDoesNotThrow(
                    () -> Owid.parse(input),
                    "reading should never throw for malformed bytes");
            assertEquals(result.isSuccess(), result.getValue() != null,
                    "the value should be present exactly when it worked");
            assertEquals(result.isSuccess(),
                    result.getStatus() == OwidParseStatus.PARSED,
                    "the status should agree with the success outcome");

            String encoded = Base64.getEncoder().encodeToString(input);
            OwidParseResult fromText = assertDoesNotThrow(
                    () -> Owid.parse(encoded),
                    "reading should never throw for malformed text");
            assertEquals(fromText.isSuccess(), fromText.getValue() != null,
                    "the value should be present exactly when it worked");
        }
    }

    /**
     * A failure carries the status and nothing taken from the input, because
     * a parse failure is often logged and the bytes came from outside.
     */
    @Test
    void failureCarriesNoneOfTheInput() {
        String secret = "cGFzc3dvcmRwYXNzd29yZHBhc3N3b3Jk";

        OwidParseResult result = Owid.parse(secret);

        ParseAssert.failed(result, OwidParseStatus.UNSUPPORTED_VERSION);
        assertEquals(OwidParseStatus.UNSUPPORTED_VERSION.name(),
                result.toString(),
                "the result should say only which status it is");
    }
}
