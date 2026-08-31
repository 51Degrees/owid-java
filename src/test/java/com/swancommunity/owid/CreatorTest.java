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

import java.util.Collections;
import org.junit.jupiter.api.Test;

/** Unit tests for the creator signing behaviour. */
class CreatorTest {

    @Test
    void emptyDomainRejected() throws OwidException {
        Crypto crypto = Crypto.generate();
        assertThrows(OwidException.class,
                () -> Creator.create("  ", crypto),
                "should reject an empty domain");
    }

    @Test
    void verifyOnlyCryptoRejected() throws OwidException {
        Crypto crypto = Crypto.generate();
        Crypto verifier = Crypto.newVerifyOnly(crypto.publicKeyPem());
        assertThrows(OwidException.class,
                () -> Creator.create("example.com", verifier),
                "should reject a crypto instance that cannot sign");
    }

    @Test
    void signSetsDomainVersionAndVerifies() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        Owid owid = creator.createString("Hello World");
        assertEquals("example.com", owid.getDomain(),
                "should set the creator domain");
        assertEquals(Version.VERSION3, owid.getVersion(),
                "should set the current version");
        assertEquals(Owid.SIGNATURE_LENGTH, owid.getSignature().length,
                "should produce a 64 byte signature");
        assertTrue(owid.verifyWithCrypto(crypto, Collections.emptyList()),
                "the signed OWID should verify");
    }

    @Test
    void signAndSelfVerifyThroughPem() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        Owid owid = creator.createString("payload");
        String encoded = owid.asBase64();
        Owid copy = ParseAssert.parsed(Owid.parse(encoded));
        assertTrue(copy.verifyWithPublicKey(crypto.publicKeyPem(),
                Collections.emptyList()), "the decoded OWID should verify");
    }

    @Test
    void tamperedSignedOwidFails() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        Owid owid = creator.createBytes(new byte[] {1, 2, 3});
        byte[] bytes = owid.asByteArray();
        bytes[bytes.length - 1] ^= 0x01;
        Owid tampered = ParseAssert.parsed(Owid.parse(bytes));
        assertFalse(tampered.verifyWithCrypto(crypto, Collections.emptyList()),
                "a tampered signature should not verify");
    }

    @Test
    void createWithOthersRoundTrips() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        Owid root = creator.createString("root");
        Owid party = creator.createString(
                "party", Collections.singletonList(root));
        assertTrue(
                party.verifyWithCrypto(
                        crypto, Collections.singletonList(root)),
                "should verify with the same others");
        assertFalse(party.verifyWithCrypto(crypto, Collections.emptyList()),
                "should fail to verify without the others");
    }

    /**
     * A creator refuses a null payload rather than producing an OWID with
     * nothing in it. This is a caller mistake in code rather than data that
     * arrived from outside, so it stays an exception.
     */
    @Test
    void nullPayloadRefused() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        assertThrows(OwidException.class,
                () -> creator.createBytes((byte[]) null),
                "should refuse a null payload");
        assertThrows(OwidException.class,
                () -> creator.createString((String) null),
                "should refuse a null payload string");
    }

    /**
     * The payload the creator was handed is copied, so a caller writing into
     * the array afterwards cannot change the OWID the signature covers.
     */
    @Test
    void payloadHandedToCreatorIsCopied() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        byte[] payload = {1, 2, 3};

        Owid owid = creator.createBytes(payload);
        payload[0] = 99;

        assertArrayEquals(new byte[] {1, 2, 3}, owid.getPayload(),
                "the OWID should keep the bytes it was signed over");
        assertTrue(owid.verifyWithCrypto(crypto, Collections.emptyList()),
                "the OWID should still verify");
    }

    @Test
    void fromPrivatePemCreatesWorkingCreator() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.fromPrivatePem("example.com",
                crypto.privateKeyPem());
        Owid owid = creator.createString("data");
        assertTrue(owid.verifyWithCrypto(crypto, Collections.emptyList()),
                "should sign with the imported key");
    }
}
