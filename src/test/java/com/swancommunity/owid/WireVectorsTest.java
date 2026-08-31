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

import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Canonical wire format vectors. Each shared base 64 string is decoded to
 * bytes, parsed to an OWID, re-serialized, and the bytes are compared with the
 * original. The vectors are unpadded so the comparison is on bytes, not on the
 * re-encoded base 64 string which carries padding.
 */
class WireVectorsTest {

    private static final String CREATOR =
            "AjUxZGIudWsAKyQKAFUBAAABAWhlYWRpbmcAcG9wLXVwLnN3YW4tZGVtby51awAQ"
            + "AAAA27eOAAPSTXmKZT79iWgRagI1MWRhLnVrACskCgAQAAAAs1WelonmS0KoK6ui"
            + "N3rz1rAxJHj2rNKvV/9OMOyFlWHY/tbwpdVupNG62p3pCWCuzgV2YMEth3coZhFS"
            + "ZHXJ1mO/U/bkHhGCSG/BStI/fJcCNTFkYi51awArJAoAFAAAAO/c7j2xwwF8GN4h"
            + "OXBIb/auLhy7mftegVZqvbepqw8nVf8ByI94w9I/XLNwf5kAFpFeSeo8kwRhXqUy"
            + "UuWT7FYIi4DnOP9zyTaAY8xgMh77oUjL/QJjbXAuc3dhbi1kZW1vLnVrACskCgAC"
            + "AAAAb25Lyrbl9PDGs6VAMqgozsfxCqsVWX6pf2JyFim3zg6lLivRDqpCD921elvx"
            + "dn85/vK0msyTOMjE8buKAza/H2zBAEqEMbMuIoZL8Ji4m4ScYkpQvD3KjsLbqI5c"
            + "7+Ra/Ju43vBMp2st7QLHD4sxwPugeSBEgQRkevAm0H1a3jekMEA";

    private static final String SUPPLIER =
            "AnBvcC11cC5zd2FuLWRlbW8udWsAKyQKAAIAAAABA6Ljm9cxZfnmwRMjv4MQ0PrA"
            + "jf8y29Ru0sjZG5R+mkjBtQD9J02xZQIk5czsKJzOl6IkOPvbPSGakxyq0HPLX+w";

    private static final String BAD =
            "AmJhZHNzcC5zd2FuLWRlbW8udWsAKyQKAAIAAAABAxu+OOtismihze3LlcNuvT2W"
            + "XNTGSiogw36t85HLwL6YdV4i9kYDCdsP54RS8on/roKKASyh19TpcUQxkIRALFk";

    private static byte[] decode(String value) {
        return Base64.getMimeDecoder().decode(value);
    }

    /**
     * Each vector also reads straight from its unpadded base 64 form, so the
     * library's own decoder is shown to accept what the vectors carry.
     */
    @Test
    void vectorsReadFromUnpaddedBase64() {
        for (String vector : new String[] {CREATOR, SUPPLIER, BAD}) {
            Owid owid = ParseAssert.parsed(Owid.parse(vector));
            assertArrayEquals(decode(vector),
                    assertDoesNotThrow(owid::asByteArray),
                    "should read the same bytes from the encoded form");
        }
    }

    @Test
    void creatorRoundTripsByteExact() throws OwidException {
        byte[] original = decode(CREATOR);
        Owid owid = ParseAssert.parsed(Owid.parse(original));
        assertEquals("51db.uk", owid.getDomain(), "should read the domain");
        assertEquals(Version.VERSION2, owid.getVersion(),
                "should read version 2");
        assertEquals(341, owid.getPayload().length,
                "should read the payload length");
        assertArrayEquals(original, owid.asByteArray(),
                "should serialize byte for byte");
    }

    @Test
    void supplierRoundTripsByteExact() throws OwidException {
        byte[] original = decode(SUPPLIER);
        Owid owid = ParseAssert.parsed(Owid.parse(original));
        assertEquals("pop-up.swan-demo.uk", owid.getDomain(),
                "should read the domain");
        assertArrayEquals(new byte[] {0x01, 0x03}, owid.getPayload(),
                "should read the two payload bytes");
        assertEquals("AQM=", owid.payloadAsBase64(),
                "should encode the payload as base 64");
        assertEquals("0103", owid.payloadAsPrintable(),
                "should print the payload as hex");
        assertArrayEquals(original, owid.asByteArray(),
                "should serialize byte for byte");
    }

    @Test
    void badParsesAndRoundTrips() throws OwidException {
        byte[] original = decode(BAD);
        Owid owid = ParseAssert.parsed(Owid.parse(original));
        assertEquals("badssp.swan-demo.uk", owid.getDomain(),
                "should read the domain");
        assertArrayEquals(original, owid.asByteArray(),
                "should serialize byte for byte");
    }
}
