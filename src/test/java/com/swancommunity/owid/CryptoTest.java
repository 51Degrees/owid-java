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

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Unit tests for the crypto signing and verification. */
class CryptoTest {

    private static final byte[] TEST_PAYLOAD =
            "test".getBytes(StandardCharsets.UTF_8);

    @Test
    void invalidPublicPem() {
        assertThrows(OwidException.class,
                () -> Crypto.newVerifyOnly("invalid"),
                "bad public PEM should error");
    }

    @Test
    void invalidPrivatePem() {
        assertThrows(OwidException.class,
                () -> Crypto.newSignOnly("invalid"),
                "bad private PEM should error");
    }

    @Test
    void emptyPublicPem() {
        OwidException e = assertThrows(OwidException.class,
                () -> Crypto.newVerifyOnly(""),
                "empty public PEM should error");
        assertEquals("public key PEM is empty", e.getMessage(),
                "should use the clear empty message");
    }

    @Test
    void emptyPrivatePem() {
        OwidException e = assertThrows(OwidException.class,
                () -> Crypto.newSignOnly("   "),
                "whitespace private PEM should error");
        assertEquals("private key PEM is empty", e.getMessage(),
                "should use the clear empty message");
    }

    @Test
    void nullPemRejected() {
        assertThrows(OwidException.class, () -> Crypto.newVerifyOnly(null),
                "null public PEM should error");
        assertThrows(OwidException.class, () -> Crypto.newSignOnly(null),
                "null private PEM should error");
    }

    @Test
    void signAndVerifyViaPem() throws OwidException {
        Crypto crypto = Crypto.generate();
        String privatePem = crypto.privateKeyPem();
        String publicPem = crypto.publicKeyPem();
        Crypto signer = Crypto.newSignOnly(privatePem);
        Crypto verifier = Crypto.newVerifyOnly(publicPem);
        byte[] signature = signer.signByteArray(TEST_PAYLOAD);
        assertEquals(Owid.SIGNATURE_LENGTH, signature.length,
                "should produce a 64 byte signature");
        assertTrue(verifier.verifyByteArray(TEST_PAYLOAD, signature),
                "signature should be valid");
    }

    @Test
    void signOnlyCanAlsoVerify() throws OwidException {
        Crypto crypto = Crypto.generate();
        Crypto signer = Crypto.newSignOnly(crypto.privateKeyPem());
        assertTrue(signer.canSign(), "should be able to sign");
        assertTrue(signer.canVerify(), "derived public key should verify");
        byte[] signature = signer.signByteArray(TEST_PAYLOAD);
        assertTrue(signer.verifyByteArray(TEST_PAYLOAD, signature),
                "should verify its own signature");
    }

    @Test
    void verifyOnlyCannotSign() throws OwidException {
        Crypto crypto = Crypto.generate();
        Crypto verifier = Crypto.newVerifyOnly(crypto.publicKeyPem());
        assertFalse(verifier.canSign(), "verify only should not sign");
        assertThrows(OwidException.class,
                () -> verifier.signByteArray(TEST_PAYLOAD),
                "verify only instance should not sign");
    }

    @Test
    void wrongLengthSignatureErrors() throws OwidException {
        Crypto crypto = Crypto.generate();
        assertThrows(OwidException.class,
                () -> crypto.verifyByteArray(TEST_PAYLOAD, new byte[63]),
                "should reject a 63 byte signature");
    }

    @Test
    void tamperedDataFailsToVerify() throws OwidException {
        Crypto crypto = Crypto.generate();
        byte[] signature = crypto.signByteArray(TEST_PAYLOAD);
        byte[] tampered = "tesx".getBytes(StandardCharsets.UTF_8);
        assertFalse(crypto.verifyByteArray(tampered, signature),
                "altered data should not verify");
    }
}
