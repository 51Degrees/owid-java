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

package com.example.owidconsumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.swancommunity.owid.Creator;
import com.swancommunity.owid.Crypto;
import com.swancommunity.owid.Owid;
import com.swancommunity.owid.OwidException;
import com.swancommunity.owid.DatedPublicKey;
import com.swancommunity.owid.OwidParseResult;
import com.swancommunity.owid.OwidSignatureStatus;
import com.swancommunity.owid.OwidVerificationResult;
import com.swancommunity.owid.PublicKeyFetch;
import com.swancommunity.owid.PublicKeySchedule;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The examples printed in the README, compiled and run.
 *
 * <p>A documented example that nothing compiles goes stale without anyone
 * noticing, and in the Go port exactly that had already happened. Keeping the
 * example here means a change to the library that would break it breaks the
 * build instead.</p>
 *
 * <p>The bodies below are the README text, with the assertions of a test
 * added around it. Change one and change the other.</p>
 */
class ReadmeExampleTest {

    @Test
    void createSerializeReadBackAndVerify() throws OwidException {
        // The creator operates a domain and holds the signing keys.
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);

        // Create a signed OWID with a payload. An OWID is signed from the
        // moment it exists, so there is never an unsigned one to hold.
        Owid owid = creator.createString("Hello World");

        // Serialize to base 64 for storage or transmission.
        String encoded = owid.asBase64();

        // Later, or elsewhere, read it back. Reading answers rather than
        // throwing, because whatever arrives from outside may not be an OWID
        // at all.
        OwidParseResult result = Owid.parse(encoded);
        if (result.isSuccess()) {
            Owid copy = result.getValue();
            String publicPem = crypto.publicKeyPem();
            boolean valid = copy.verifyWithPublicKey(
                    publicPem, Collections.<Owid>emptyList());

            assertTrue(valid, "the OWID read back should verify");
            assertEquals("Hello World", copy.payloadAsString(),
                    "should carry the payload it was created with");
        } else {
            // result.getStatus() names which of the expected problems it was,
            // and result.getValue() is null.
            org.junit.jupiter.api.Assertions.fail(
                    "the example should read back, but reported "
                            + result.getStatus());
        }
    }

    /**
     * The framed loop from the README, reading two OWIDs written one after
     * the other into the same array.
     */
    @Test
    void readingOneOwidAfterAnother() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        byte[] one = creator.createString("one").asByteArray();
        byte[] two = creator.createString("two").asByteArray();
        byte[] bytes = new byte[one.length + two.length];
        System.arraycopy(one, 0, bytes, 0, one.length);
        System.arraycopy(two, 0, bytes, one.length, two.length);

        List<String> payloads = new ArrayList<String>();

        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            OwidParseResult result = Owid.parse(buffer);
            if (result.isSuccess() == false) {
                // buffer is still at the start of the frame that failed, and
                // result.getStatus() says why.
                break;
            }
            payloads.add(result.getValue().payloadAsString());
        }

        assertEquals(2, payloads.size(), "should have read both OWIDs");
        assertEquals("one", payloads.get(0), "should read the first payload");
        assertEquals("two", payloads.get(1), "should read the second payload");
        assertFalse(buffer.hasRemaining(),
                "the two OWIDs should account for every byte");
    }

    @Test
    void chainingCoversTheOtherOwids() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);

        Owid root = creator.createString("root");
        Owid party = creator.createString(
                "party", Collections.singletonList(root));

        // Verifies with the root as the single other, fails without it.
        assertTrue(
                party.verifyWithCrypto(
                        crypto, Collections.singletonList(root)),
                "should verify with the same others");
        assertFalse(
                party.verifyWithCrypto(crypto, Collections.<Owid>emptyList()),
                "should fail to verify without the others");
    }

    /**
     * The schedule example from the README, choosing between two weekly keys
     * by the date the identifier carries.
     */
    @Test
    void aScheduleChoosesTheKeyThatWasInForce() throws OwidException {
        Crypto lastWeek = Crypto.generate();
        Crypto thisWeek = Crypto.generate();
        String lastWeekPem = lastWeek.publicKeyPem();
        String thisWeekPem = thisWeek.publicKeyPem();
        Owid owid = Creator.create("example.com", thisWeek)
                .createString("signed this week");

        PublicKeySchedule schedule = PublicKeySchedule.of(Arrays.asList(
                DatedPublicKey.of(
                        Instant.parse("2026-08-24T00:00:00Z"), lastWeekPem),
                DatedPublicKey.of(
                        Instant.parse("2026-08-31T00:00:00Z"), thisWeekPem)));
        OwidVerificationResult result = schedule.verify(
                owid, Collections.<Owid>emptyList());

        assertEquals(OwidSignatureStatus.SIGNATURE_VALID, result.getStatus(),
                "should choose the key that was in force and verify");
        assertTrue(result.isValid(), "the signature was examined and matched");
    }

    /**
     * The fetch example from the README. The creator domain used here is in
     * the reserved {@code .invalid} name space so that the test never reaches
     * the network of whoever is running it, which shows the shape of the call
     * and the status a key that cannot be obtained produces. The case where
     * the key does arrive and the identifier verifies is covered by
     * {@code DatedKeyFetchTest}, which stands up a key end point on the
     * loopback address serving the real published schedule.
     */
    @Test
    void fetchingTheKeyFromTheCreatorDomain() throws OwidException {
        Owid owid = Creator.create("owid.invalid", Crypto.generate())
                .createString("signed by a creator that cannot be reached");

        OwidVerificationResult result = PublicKeyFetch.verify(
                owid, "https", Collections.<Owid>emptyList());
        if (result.getStatus() == OwidSignatureStatus.KEY_UNAVAILABLE) {
            // The key could not be obtained, so the signature was never
            // examined. Only SIGNATURE_INVALID means the identifier should
            // be distrusted.
            assertFalse(result.isValid(),
                    "a signature that was never examined is not valid");
        }

        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE, result.getStatus(),
                "a domain that cannot be reached leaves the signature "
                        + "unjudged");
    }
}
