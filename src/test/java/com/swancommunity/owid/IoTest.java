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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the binary write helpers, each paired with the read that has
 * to agree with it.
 *
 * <p>Reading is no longer a helper a test can call field by field, because it
 * now walks a whole envelope and reports why rather than throwing, so each
 * test here checks the bytes the writer produced and then reads them back
 * through a complete envelope.</p>
 */
class IoTest {

    private static final byte[] PAYLOAD = {0x0A, 0x0B};

    @Test
    void dateRoundtripVersion2() throws OwidException {
        Instant date = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        long minutes = Duration.between(Io.baseDate(), date).toMinutes();

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Io.writeDate(buffer, date, Version.VERSION2);
        assertEquals(4, buffer.size(), "should use four bytes for version 2");

        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        Envelope.writeLittleEndian(expected, minutes);
        assertArrayEquals(expected.toByteArray(), buffer.toByteArray(),
                "should write the minute count little endian");

        Owid owid = ParseAssert.parsed(Owid.parse(
                Envelope.version3(Envelope.DOMAIN, minutes, PAYLOAD.length,
                        PAYLOAD, Envelope.signature())));
        assertEquals(date, owid.getDate(),
                "should read back the same minute count");
    }

    @Test
    void dateRoundtripVersion1() throws OwidException {
        Instant date = Io.baseDate().plus(Duration.ofHours(12_345));

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Io.writeDate(buffer, date, Version.VERSION1);
        assertEquals(2, buffer.size(), "should use two bytes for version 1");
        assertArrayEquals(new byte[] {0x30, 0x39}, buffer.toByteArray(),
                "should write the hour count big endian");

        Owid owid = ParseAssert.parsed(Owid.parse(
                Envelope.version1(Envelope.DOMAIN, 12_345L, PAYLOAD.length,
                        PAYLOAD, Envelope.signature())));
        assertEquals(date, owid.getDate(), "should keep hour granularity");
    }

    @Test
    void dateBeforeBaseErrors() {
        Instant date = Io.baseDate().minus(Duration.ofMinutes(1));
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        assertThrows(OwidException.class,
                () -> Io.writeDate(buffer, date, Version.VERSION3),
                "should reject dates before the base date");
    }

    @Test
    void stringRoundtrip() throws OwidException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Io.writeString(buffer, "example.com");
        byte[] bytes = buffer.toByteArray();
        assertEquals(0, bytes[bytes.length - 1], "should be null terminated");

        Owid owid = ParseAssert.parsed(Owid.parse(
                Envelope.version3("example.com", 1000L, PAYLOAD.length,
                        PAYLOAD, Envelope.signature())));
        assertEquals("example.com", owid.getDomain(),
                "should match the original string");
    }

    @Test
    void stringWithNullRejected() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        assertThrows(OwidException.class,
                () -> Io.writeString(buffer, "a" + (char) 0 + "b"),
                "should reject a domain containing a null character");
    }

    @Test
    void uint32LittleEndian() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Io.writeUInt32(buffer, 0x0A242B01L);
        assertArrayEquals(new byte[] {0x01, 0x2B, 0x24, 0x0A},
                buffer.toByteArray(), "should be little endian");

        // The same four bytes read back through the date field, which is the
        // one place a whole unsigned 32 bit value reaches the reader.
        Owid owid = ParseAssert.parsed(Owid.parse(
                Envelope.version3(Envelope.DOMAIN, 0x0A242B01L, PAYLOAD.length,
                        PAYLOAD, Envelope.signature())));
        assertEquals(Io.baseDate().plus(Duration.ofMinutes(0x0A242B01L)),
                owid.getDate(), "should round trip the unsigned value");
    }

    @Test
    void signatureRoundtrip() throws OwidException {
        byte[] signature = new byte[Owid.SIGNATURE_LENGTH];
        for (int i = 0; i < signature.length; i++) {
            signature[i] = (byte) i;
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Io.writeSignature(buffer, signature);
        assertArrayEquals(signature, buffer.toByteArray(),
                "should write the signature bytes unchanged");

        Owid owid = ParseAssert.parsed(Owid.parse(
                Envelope.version3(Envelope.DOMAIN, 1000L, PAYLOAD.length,
                        PAYLOAD, signature)));
        assertArrayEquals(signature, owid.getSignature(),
                "should round trip the signature");
    }

    @Test
    void wrongLengthSignatureRejected() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        assertThrows(OwidException.class,
                () -> Io.writeSignature(buffer, new byte[10]),
                "should reject a signature that is not 64 bytes");
    }
}
