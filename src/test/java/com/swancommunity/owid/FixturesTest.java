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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Cross language signed fixtures. Each set of OWIDs was produced by a separate
 * implementation and signed with the matching public key. The test verifies
 * the real signatures, the chain relationship, and that flipping the last
 * signature byte breaks verification.
 */
class FixturesTest {

    /** A set of fixtures produced by one implementation with one key. */
    private static final class Fixtures {

        private final String spki;
        private final String simple;
        private final String utf8;
        private final String chainParty;
        private final String chainRoot;

        Fixtures(String spki, String simple, String utf8,
                String chainParty, String chainRoot) {
            this.spki = spki;
            this.simple = simple;
            this.utf8 = utf8;
            this.chainParty = chainParty;
            this.chainRoot = chainRoot;
        }

        String spki() {
            return spki;
        }

        String simple() {
            return simple;
        }

        String utf8() {
            return utf8;
        }

        String chainParty() {
            return chainParty;
        }

        String chainRoot() {
            return chainRoot;
        }
    }

    private static final String UTF8_TEXT = "Zürich ❤ OWID £€";

    private static final Fixtures GO = new Fixtures(
            "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeO51FrQ8AmCFjLnePUH1qQ4GWGxj\n"
            + "1aL5ux6vNJFSRnGTVc5YC8kEwqfOaMEjVWqt4Gbq4+lEnIAgTl76YAGpcA==\n"
            + "-----END PUBLIC KEY-----",
            "A2dvLnN3YW4tZGVtby51awA/vTMABwAAAGV4YW1wbGVPIQZ/uhIjVxrROjMDfcAk"
            + "Rk8U4fYacm0Ck4aOxoRDJPK/QrKavqZqCf7cCKbNuJ0aA7GhVeuy4ojeSzNX56Qn",
            "A2dvLnN3YW4tZGVtby51awA/vTMAFgAAAFrDvHJpY2gg4p2kIE9XSUQgwqPigqzx"
            + "Y+4QgUGt84xC9HxHmHXDt+wcB0Y9a6E+Txm2F147Qacbp0CtrF8x7QCWZfkcKCKN"
            + "GSM8hYZEfYjJtViG+tA+",
            "A2dvLnN3YW4tZGVtby51awA/vTMABQAAAHBhcnR5l7NyNmFw2lxqc4DKJWoq0UVd"
            + "5ujGV/+fvVxqYTRlwCFxaSuwvnhLQQHjX5spxWb4O08IeuiuGCat1WFB/Wqlyw==",
            "A2dvLnN3YW4tZGVtby51awA/vTMABAAAAHJvb3R/bEqzG8gAy9yTF1UMEtOlYXBB"
            + "mn3a20jxXq5NmxIC8iuZvduOXKMf+K8VoAapkWwfpoDKQHS09IhljasZqC0k");

    private static final Fixtures DOTNET = new Fixtures(
            "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEec6dTi0JOYGP78lw7/zAjp3r73fZ\n"
            + "A7zSi4Ov90sVxgmqZ4cI1sbj7AbsnBhqJDe5Hu14gDBjZWErL7KpkjEl0A==\n"
            + "-----END PUBLIC KEY-----",
            "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAcAAABleGFtcGxlVegwXS00P/DU2FJb"
            + "Ljof8qc/BwrffhbKJkV42pqFd7nUD+KR/DxxRSfLlm77/kAyR/dLOcwEetjN1z9U"
            + "Wzyh0w==",
            "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zABYAAABaw7xyaWNoIOKdpCBPV0lEIMKj"
            + "4oKsVuaeaDUej0sF+cHfYj/icDBmlBLOviC6ZE28am8EtY+IGuesFcg2rKMybcsA"
            + "xMmnrDtF2xsk1cJvHgoIYpSJJQ==",
            "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAUAAABwYXJ0eXtD6H4R7GbvRyFU+bCK"
            + "gjMAZFFm8KHln80XPwQOBb/Ub9EZfE4Ml3ueRkKX51+MD98RFgTSmjbqrAnzFkLl"
            + "ilA=",
            "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAQAAAByb290fErj2LccPYCduWUW8vY2"
            + "aBjrecDfnTpVpv3+SESJMFW5pcuPKEQik2rC0fWEoB5Vr6e0k5inrhUGiF2c2Y2Y"
            + "Dw==");

    private static final Fixtures RUST = new Fixtures(
            "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQcDroVnBAGAvy1SyUz4MyFxP16ki\n"
            + "aPLulPz92rmbDbFKB6p0xl3iatZQ0uADa+F9cZeemLKtlfPaaue/KvNQOw==\n"
            + "-----END PUBLIC KEY-----",
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAHAAAAZXhhbXBsZQtzvD+xirWingyfDxby"
            + "kxurSxK4XdixdGR5lR0xnHmv2IFSsVCub2Jd1jRg/vQJ8XnXuNljRp/ErjSOMMQo"
            + "5CI=",
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAWAAAAWsO8cmljaCDinaQgT1dJRCDCo+KC"
            + "rDHenDds+W587AzXpBb94gmLOloeBJTlHnjCkez4Dz2yAPtjcoQ6M/ZUWDIobtJH"
            + "E5n9a81pTsn/Kvi74Azzx4s=",
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAFAAAAcGFydHmJ7qaxWgIZUHmGOQb2xC+R"
            + "uZNwrkMmo1SA9/MfI4SoEpRYdnteXAKUQXxTOK3lmQ3Qz3UwBB6gBb3Q8hi1Wx0R",
            "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAEAAAAcm9vdFd0+QLaBLGPyBrQO+VNunBI"
            + "QZzw8/lhEiDOKTx36Dc93A0n0fzPDMt/C+BdWMqhnL4nVvyurb3IHR7DUAmgmO0=");

    /** Returns a copy of the bytes with the final byte flipped. */
    private static byte[] flipLastByte(byte[] bytes) {
        byte[] copy = bytes.clone();
        copy[copy.length - 1] ^= 0x01;
        return copy;
    }

    private void runFixtures(Fixtures fixtures) throws OwidException {
        Crypto crypto = Crypto.newVerifyOnly(fixtures.spki());
        List<Owid> none = Collections.emptyList();

        Owid simple = ParseAssert.parsed(Owid.parse(fixtures.simple()));
        assertTrue(simple.verifyWithCrypto(crypto, none),
                "simple should verify");
        assertTrue(simple.verifyWithPublicKey(fixtures.spki(), none),
                "simple should verify by public key PEM");

        Owid utf8 = ParseAssert.parsed(Owid.parse(fixtures.utf8()));
        assertTrue(utf8.verifyWithCrypto(crypto, none), "utf8 should verify");
        org.junit.jupiter.api.Assertions.assertEquals(UTF8_TEXT,
                utf8.payloadAsString(), "utf8 payload text should match");

        Owid root = ParseAssert.parsed(Owid.parse(fixtures.chainRoot()));
        assertTrue(root.verifyWithCrypto(crypto, none),
                "chain root should verify alone");

        Owid party = ParseAssert.parsed(Owid.parse(fixtures.chainParty()));
        assertTrue(party.verifyWithCrypto(crypto, Collections.singletonList(root)),
                "chain party should verify with the root as the other");
        assertFalse(party.verifyWithCrypto(crypto, none),
                "chain party should fail with no others");

        // Each fixture with its last signature byte flipped must fail.
        for (String encoded : new String[] {fixtures.simple(), fixtures.utf8(),
                fixtures.chainRoot()}) {
            byte[] tampered = flipLastByte(Base64.getMimeDecoder().decode(encoded));
            Owid owid = ParseAssert.parsed(Owid.parse(tampered));
            assertFalse(owid.verifyWithCrypto(crypto, none),
                    "a flipped signature byte should break verification");
        }
        byte[] tamperedParty =
                flipLastByte(Base64.getMimeDecoder().decode(fixtures.chainParty()));
        Owid party2 = ParseAssert.parsed(Owid.parse(tamperedParty));
        assertFalse(party2.verifyWithCrypto(crypto, Collections.singletonList(root)),
                "a flipped party signature byte should break verification");
    }

    @Test
    void goFixtures() throws OwidException {
        runFixtures(GO);
    }

    @Test
    void dotnetFixtures() throws OwidException {
        runFixtures(DOTNET);
    }

    @Test
    void rustFixtures() throws OwidException {
        runFixtures(RUST);
    }
}
