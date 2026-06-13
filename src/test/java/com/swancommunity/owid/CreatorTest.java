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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;
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
        Owid owid = creator.signString("Hello World");
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
        Owid owid = creator.signString("payload");
        String encoded = owid.asBase64();
        Owid copy = Owid.fromBase64(encoded);
        assertTrue(copy.verifyWithPublicKey(crypto.publicKeyPem(),
                Collections.emptyList()), "the decoded OWID should verify");
    }

    @Test
    void tamperedSignedOwidFails() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        Owid owid = creator.signBytes(new byte[] {1, 2, 3});
        byte[] bytes = owid.asByteArray();
        bytes[bytes.length - 1] ^= 0x01;
        Owid tampered = Owid.fromByteArray(bytes);
        assertFalse(tampered.verifyWithCrypto(crypto, Collections.emptyList()),
                "a tampered signature should not verify");
    }

    @Test
    void signWithOthersRoundTrips() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        Owid root = creator.signString("root");
        Owid party = new Owid();
        party.setPayload("party".getBytes());
        creator.signWithOthers(party, List.of(root));
        assertTrue(party.verifyWithCrypto(crypto, List.of(root)),
                "should verify with the same others");
        assertFalse(party.verifyWithCrypto(crypto, Collections.emptyList()),
                "should fail to verify without the others");
    }

    @Test
    void fromPrivatePemCreatesWorkingCreator() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.fromPrivatePem("example.com",
                crypto.privateKeyPem());
        Owid owid = creator.signString("data");
        assertTrue(owid.verifyWithCrypto(crypto, Collections.emptyList()),
                "should sign with the imported key");
    }
}
