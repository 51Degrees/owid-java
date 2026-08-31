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
import java.util.Arrays;

/**
 * Builds serialized OWIDs a byte at a time for the tests.
 *
 * <p>The bytes are written by hand rather than through the library, so a test
 * of the reader does not depend on the writer it is checking the reader
 * against, and so a test can make the declared payload length and the bytes
 * present disagree in ways the writer would never produce.</p>
 */
final class Envelope {

    /** The domain used wherever a test does not care what the domain is. */
    static final String DOMAIN = "51d.es";

    private Envelope() {
    }

    /** A byte array of the length given, every byte set to the value. */
    static byte[] filled(int length, byte value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }

    /**
     * A signature shaped run of bytes, being the right length and nothing
     * more.
     */
    static byte[] signature() {
        return filled(Owid.SIGNATURE_LENGTH, (byte) 0x99);
    }

    /**
     * A version 3 envelope, being the version byte, the domain with its
     * terminator, four minute bytes, the declared payload length, the payload
     * bytes given and the signature bytes given.
     */
    static byte[] version3(String domain, long minutes, long declaredLength,
            byte[] payload, byte[] signature) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(Version.VERSION3.asByte());
        writeDomain(stream, domain.getBytes(StandardCharsets.UTF_8));
        writeLittleEndian(stream, minutes);
        writeLittleEndian(stream, declaredLength);
        stream.write(payload, 0, payload.length);
        stream.write(signature, 0, signature.length);
        return stream.toByteArray();
    }

    /** The smallest well formed version 3 envelope carrying the payload. */
    static byte[] version3(byte[] payload) {
        return version3(DOMAIN, 1000L, payload.length, payload, signature());
    }

    /**
     * A version 1 envelope, whose date is two big endian bytes counting hours
     * rather than four little endian bytes counting minutes.
     */
    static byte[] version1(String domain, long hours, long declaredLength,
            byte[] payload, byte[] signature) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(Version.VERSION1.asByte());
        writeDomain(stream, domain.getBytes(StandardCharsets.UTF_8));
        stream.write((int) ((hours >> 8) & 0xFF));
        stream.write((int) (hours & 0xFF));
        writeLittleEndian(stream, declaredLength);
        stream.write(payload, 0, payload.length);
        stream.write(signature, 0, signature.length);
        return stream.toByteArray();
    }

    private static void writeDomain(ByteArrayOutputStream stream,
            byte[] domain) {
        stream.write(domain, 0, domain.length);
        stream.write(0);
    }

    static void writeLittleEndian(ByteArrayOutputStream stream, long value) {
        stream.write((int) (value & 0xFF));
        stream.write((int) ((value >> 8) & 0xFF));
        stream.write((int) ((value >> 16) & 0xFF));
        stream.write((int) ((value >> 24) & 0xFF));
    }
}
