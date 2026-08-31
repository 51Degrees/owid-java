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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Asking whether a signature is genuine has to keep "does not match" apart
 * from "could not check".
 *
 * <p>A key that cannot be obtained or cannot be decoded leaves the signature
 * unjudged. Reporting that as invalid would tell a caller an identifier had
 * been tampered with when all that happened is an outage, and a caller acting
 * on it would reject good identifiers.</p>
 *
 * <p>Every member of {@link OwidSignatureStatus} is exercised here except
 * {@link OwidSignatureStatus#IMPLEMENTATION_CAPACITY_EXCEEDED}, which needs
 * an OWID and its chain to approach the two gigabyte limit of a Java array
 * and so cannot be built in a suite that has to run on an ordinary machine.
 * The reason is recorded on the member itself as well.</p>
 */
class SignatureStatusTest {

    private static final List<Owid> NONE = Collections.<Owid>emptyList();

    private static Crypto crypto() throws OwidException {
        return Crypto.generate();
    }

    /** A genuine signature is the only thing that reports valid. */
    @Test
    void genuineSignatureIsValid() throws OwidException {
        Crypto crypto = crypto();
        Owid owid = Creator.create("example.com", crypto)
                .createString("payload");

        OwidVerificationResult result = owid.verify(crypto, NONE);

        assertTrue(result.isValid(), "a genuine signature should be valid");
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID, result.getStatus(),
                "should report the signature as valid");
    }

    /** The same question answered from the public key PEM. */
    @Test
    void genuineSignatureIsValidThroughPem() throws OwidException {
        Crypto crypto = crypto();
        Owid owid = Creator.create("example.com", crypto)
                .createString("payload");

        OwidVerificationResult result = owid.verify(
                crypto.publicKeyPem(), NONE);

        assertEquals(OwidSignatureStatus.SIGNATURE_VALID, result.getStatus(),
                "should report the signature as valid");
    }

    /**
     * A signature checked against the wrong key does not match. This is the
     * one status that means the identifier should be distrusted.
     */
    @Test
    void wrongKeyIsSignatureInvalid() throws OwidException {
        Owid owid = Creator.create("example.com", crypto())
                .createString("payload");

        OwidVerificationResult result =
                owid.verify(crypto(), NONE);

        assertFalse(result.isValid(), "the signature should not be valid");
        assertEquals(OwidSignatureStatus.SIGNATURE_INVALID, result.getStatus(),
                "a well formed signature that does not match is invalid");
    }

    /**
     * No key at all leaves the signature unexamined, which is not the same as
     * the signature being wrong.
     */
    @Test
    void noKeyIsKeyUnavailable() throws OwidException {
        Owid owid = Creator.create("example.com", crypto())
                .createString("payload");

        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                owid.verify((Crypto) null, NONE).getStatus(),
                "a missing crypto instance should not judge the signature");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                owid.verify((String) null, NONE).getStatus(),
                "a missing PEM should not judge the signature");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                owid.verify("   ", NONE).getStatus(),
                "an empty PEM should not judge the signature");
    }

    /**
     * Key material that arrived but cannot be used is the key's fault and not
     * the identifier's. On 30 August 2026 the key end points served PEM a
     * strict parser rejects and every offline verification failed while the
     * keys and identifiers were both fine, which as an invalid signature
     * would have read as an attack.
     */
    @Test
    void undecodableKeyIsInvalidKey() throws OwidException {
        Owid owid = Creator.create("example.com", crypto())
                .createString("payload");

        assertEquals(OwidSignatureStatus.INVALID_KEY,
                owid.verify("not a PEM", NONE)
                        .getStatus(),
                "material that is not a key should be reported as the key");
        assertEquals(OwidSignatureStatus.INVALID_KEY,
                owid.verify(
                        "-----BEGIN PUBLIC KEY-----\nAAAA\n"
                                + "-----END PUBLIC KEY-----\n", NONE)
                        .getStatus(),
                "a PEM whose body is not a key should be reported as the key");
    }

    /**
     * A signature field that is not the length the version requires cannot be
     * checked, and saying so is not the same as saying the signature is
     * wrong.
     *
     * <p>The OWID is built here through the package private constructor,
     * because a consumer cannot produce one: both routes an OWID arrives by,
     * being a read and a creator, settle the signature at 64 bytes. The
     * status is part of the cross language vocabulary and other surfaces can
     * be handed a signature field on its own, so the branch is exercised from
     * inside the package where it can be reached.</p>
     */
    @Test
    void wrongLengthSignatureIsInvalidSignatureLength() throws OwidException {
        Owid noSignature = new Owid(Version.current(), "example.com",
                Io.baseDate(), new byte[0], new byte[0]);
        Owid shortSignature = new Owid(Version.current(), "example.com",
                Io.baseDate(), new byte[0],
                Envelope.filled(Owid.SIGNATURE_LENGTH - 1, (byte) 1));

        assertEquals(OwidSignatureStatus.INVALID_SIGNATURE_LENGTH,
                noSignature.verify(crypto(), NONE).getStatus(),
                "no signature is not the same as a signature that is wrong");
        assertEquals(OwidSignatureStatus.INVALID_SIGNATURE_LENGTH,
                shortSignature.verify(crypto(), NONE).getStatus(),
                "a 63 byte signature is not a signature that is wrong");
    }

    /**
     * A field that cannot be encoded stops the check before any cryptography,
     * and that is the library failing rather than the identifier being wrong.
     * Only the library can produce this, because a caller cannot build an
     * OWID with a domain of its own choosing.
     */
    @Test
    void unencodableFieldIsVerificationError() throws OwidException {
        StringBuilder domain = new StringBuilder();
        while (domain.length() <= Io.MAXIMUM_DOMAIN_LENGTH) {
            domain.append('a');
        }
        Owid owid = new Owid(Version.current(), domain.toString(),
                Io.baseDate(), new byte[0],
                Envelope.filled(Owid.SIGNATURE_LENGTH, (byte) 1));

        assertEquals(OwidSignatureStatus.VERIFICATION_ERROR,
                owid.verify(crypto(), NONE).getStatus(),
                "a field that cannot be encoded is not an invalid signature");
    }

    /**
     * The boolean surfaces still answer the same question for callers that
     * only need yes or no, and still raise for a key they cannot import
     * rather than answering no.
     */
    @Test
    void booleanSurfacesKeepTheirBehaviour() throws OwidException {
        Crypto crypto = crypto();
        Owid owid = Creator.create("example.com", crypto)
                .createString("payload");

        assertTrue(owid.verifyWithCrypto(crypto, NONE),
                "a genuine signature should verify");
        assertTrue(owid.verifyWithPublicKey(crypto.publicKeyPem(), NONE),
                "a genuine signature should verify through the PEM");
        assertFalse(owid.verifyWithCrypto(crypto(), NONE),
                "a signature checked against another key should not verify");
    }
}
