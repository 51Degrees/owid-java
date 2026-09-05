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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Fetching the key that was in force when an identifier was signed, from the
 * well known end point on the creator domain.
 *
 * <p>The live end point answers 401 without a credential, so these tests run
 * against a stand in on the loopback address which serves the real published
 * 51d.es schedule. The URL under test is the one the library builds, with
 * only the host replaced, so a fault in the path or the query is caught
 * here.</p>
 */
class DatedKeyFetchTest {

    /** No other OWIDs were covered by the signature on the fixture. */
    private static final List<Owid> ALONE = Collections.emptyList();

    /** The end points started by a test, stopped when the test ends. */
    private final List<KeyEndPoint> started = new ArrayList<KeyEndPoint>();

    @BeforeEach
    void emptyTheCache() {
        // Keys are held against the URL they were fetched from, and a test
        // that counts requests has to start from nothing held.
        PublicKeyFetch.clearCache();
    }

    @AfterEach
    void stopEndPoints() {
        for (KeyEndPoint endPoint : started) {
            endPoint.stop();
        }
        started.clear();
        PublicKeyFetch.clearCache();
    }

    /** Starts a stand in end point and stops it when the test ends. */
    private KeyEndPoint endPoint(KeyEndPoint.Answer answer)
            throws IOException, OwidException {
        KeyEndPoint endPoint = KeyEndPoint.start(answer);
        started.add(endPoint);
        return endPoint;
    }

    /**
     * The URL names the minute the identifier was created, which is the value
     * the end point selects a key by, and it names the well known path from
     * the specification.
     */
    @Test
    void urlNamesTheMinuteTheIdentifierWasCreated() throws OwidException {
        assertEquals(
                "https://51d.es/owid/api/v3/public-key?date="
                        + KeyFixtures.IDENTIFIER_MINUTES + "&format=pkcs",
                PublicKeyFetch.publicKeyUrl(KeyFixtures.identifier(),
                        "https"),
                "should ask 51d.es for the key in force on 4 September 2026");
    }

    /**
     * The version in the path comes from the version byte of the identifier
     * rather than from a constant, so an identifier written by an earlier
     * version asks the end point that serves that version.
     */
    @Test
    void urlUsesTheVersionTheIdentifierCarries() throws OwidException {
        Owid version2 = crafted(Version.VERSION2, "example.com",
                Instant.parse("2026-09-04T00:00:00Z"));
        assertEquals(Version.VERSION2, version2.getVersion(),
                "the crafted identifier is version 2");
        assertEquals(
                "https://example.com/owid/api/v2/public-key?date="
                        + KeyFixtures.IDENTIFIER_MINUTES + "&format=pkcs",
                PublicKeyFetch.publicKeyUrl(version2, "https"),
                "should ask the version 2 end point");
    }

    /** A newly signed OWID names the minute it was signed. */
    @Test
    void urlOfANewlySignedOwidNamesItsOwnMinute() throws OwidException {
        Creator creator = Creator.create("example.com", Crypto.generate());
        Owid owid = creator.createString("payload");
        assertEquals(
                "https://example.com/owid/api/v3/public-key?date="
                        + Io.minutesSinceBase(owid.getDate())
                        + "&format=pkcs",
                PublicKeyFetch.publicKeyUrl(owid, "https"),
                "should name the minute the OWID was signed");
    }

    /**
     * The fetch asks for the key in force when the identifier was signed and
     * verifies it, with the identifier signed in a week earlier than the one
     * the end point counts as current. This is the case a missing date
     * parameter broke in the Rust port, and it is the case Java had no
     * answer for at all.
     */
    @Test
    void datedFetchVerifiesAnIdentifierFromAnEarlierKeyWeek()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                PublicKeyFetch.verifyAtUrl(owid, endPoint.urlFor(owid), ALONE)
                        .getStatus(),
                "should verify against the key in force when it was signed");
        assertEquals(
                Collections.singletonList(
                        Long.toString(KeyFixtures.IDENTIFIER_MINUTES)),
                endPoint.dates(),
                "the request should name the minute the identifier was "
                        + "created");
    }

    /**
     * The same identifier against the same end point without the date, which
     * is the request a port that forgets the date makes. The end point
     * answers with the key in force at the moment of the request, ten days
     * after the identifier was signed, the signature does not match that
     * key, and a genuine identifier reads as a forgery.
     */
    @Test
    void undatedFetchLeavesAnEarlierWeeksIdentifierUnverified()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        String undated = endPoint.base()
                + "/owid/api/v3/public-key?format=pkcs";
        assertEquals(OwidSignatureStatus.SIGNATURE_INVALID,
                PublicKeyFetch.verifyAtUrl(owid, undated, ALONE).getStatus(),
                "an undated request gets the key in force at the request, "
                        + "which did not sign it");
        assertEquals(Collections.singletonList((String) null),
                endPoint.dates(),
                "the request carried no date");
    }

    /**
     * An end point that cannot serve a key for the date leaves the signature
     * unjudged rather than reporting a genuine identifier as a forgery.
     */
    @Test
    void aKeyTheEndPointCannotServeIsKeyUnavailable()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        // A fortnight before the schedule begins, which no key in it covers,
        // so the end point answers 404 the way the cloud does.
        Instant before = KeyFixtures.scheduledKeys().get(0).startsAt()
                .minus(Duration.ofDays(14));
        String url = endPoint.base() + "/owid/api/v3/public-key?date="
                + Io.minutesSinceBase(before) + "&format=pkcs";
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                PublicKeyFetch.verifyAtUrl(owid, url, ALONE).getStatus(),
                "no key means the signature was never examined");
    }

    /** The refusal carries the code and the domain, not only a message. */
    @Test
    void aRefusedRequestCarriesTheStatusAndTheCode()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        final String url = endPoint.base() + "/owid/api/v3/public-key?date=0"
                + "&format=pkcs";
        PublicKeyFetchException failure = assertThrows(
                PublicKeyFetchException.class,
                () -> PublicKeyFetch.publicKeyPemAtUrl(url, "51d.es"),
                "a date the schedule does not reach is refused");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                failure.getStatus(),
                "the status says the signature was never examined");
        assertEquals(404, failure.getStatusCode(),
                "the response code is carried rather than described");
        assertEquals("51d.es", failure.getDomain(),
                "the domain asked of is carried");
    }

    /**
     * An end point that cannot be reached at all leaves the signature
     * unjudged. Nothing about the identifier is known, so calling it invalid
     * would report an outage as an attack.
     */
    @Test
    void anEndPointThatCannotBeReachedIsKeyUnavailable()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = KeyEndPoint.start();
        String url = endPoint.urlFor(owid);
        endPoint.stop();
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                PublicKeyFetch.verifyAtUrl(owid, url, ALONE).getStatus(),
                "a connection that is refused leaves the signature "
                        + "unjudged");
    }

    /**
     * Key material that arrives but cannot be read is the fault of the key
     * and not of the identifier, so it is reported apart from a signature
     * that does not match. This is the 30 August 2026 fault, where the key
     * end points served PEM a strict parser refused and every offline check
     * against them failed while the keys and the identifiers were both fine.
     */
    @Test
    void aKeyThatCannotBeReadIsInvalidKey()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.BROKEN_KEY);
        assertEquals(OwidSignatureStatus.INVALID_KEY,
                PublicKeyFetch.verifyAtUrl(owid, endPoint.urlFor(owid), ALONE)
                        .getStatus(),
                "a key that cannot be read is not a signature that does not "
                        + "match");
    }

    /**
     * The key is fetched once and answered from the cache after that, which
     * is what the specification asks for so that verifying many identifiers
     * does not mean repeating requests to another processor.
     */
    @Test
    void theKeyIsFetchedOnceAndHeldAfterThat()
            throws IOException, OwidException {
        Owid owid = KeyFixtures.identifier();
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        String url = endPoint.urlFor(owid);
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                PublicKeyFetch.verifyAtUrl(owid, url, ALONE).getStatus(),
                "the first check fetches the key");
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                PublicKeyFetch.verifyAtUrl(owid, url, ALONE).getStatus(),
                "the second check answers from the cache");
        assertEquals(1, endPoint.dates().size(),
                "the end point was asked once");
        PublicKeyFetch.clearCache();
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                PublicKeyFetch.verifyAtUrl(owid, url, ALONE).getStatus(),
                "the check still works once the cache is emptied");
        assertEquals(2, endPoint.dates().size(),
                "emptying the cache means the key is fetched again");
    }

    /**
     * Keys are held against the URL they came from, which names the minute,
     * so two identifiers from different weeks fetch two different keys, and
     * a key held for one week never answers for another. A store keyed by
     * domain alone would hand the second identifier the first one's key.
     */
    @Test
    void keysAreHeldPerRequestAndNotPerDomain()
            throws IOException, OwidException {
        KeyEndPoint endPoint = endPoint(KeyEndPoint.Answer.SCHEDULE);
        Owid earlier = crafted(Version.VERSION3, KeyFixtures.IDENTIFIER_DOMAIN,
                Instant.parse("2026-08-20T00:00:00Z"));
        Owid later = crafted(Version.VERSION3, KeyFixtures.IDENTIFIER_DOMAIN,
                Instant.parse("2026-09-04T00:00:00Z"));
        String first = PublicKeyFetch.publicKeyPemAtUrl(
                endPoint.urlFor(earlier), KeyFixtures.IDENTIFIER_DOMAIN);
        String second = PublicKeyFetch.publicKeyPemAtUrl(
                endPoint.urlFor(later), KeyFixtures.IDENTIFIER_DOMAIN);
        assertNotEquals(first, second, "two weeks, two keys");
        assertEquals(2, endPoint.dates().size(), "one request per week");
        assertEquals(first, PublicKeyFetch.publicKeyPemAtUrl(
                endPoint.urlFor(earlier), KeyFixtures.IDENTIFIER_DOMAIN),
                "the held key is the one fetched for that week");
        assertEquals(2, endPoint.dates().size(),
                "a week already held is not asked for again");
    }

    /**
     * The domain arrives inside an OWID, which came from outside, so a value
     * that would change the shape of the URL rather than name a host in it is
     * refused before any request is made.
     */
    @Test
    void aDomainThatIsNotADomainNameIsRefused() throws OwidException {
        final Owid owid = crafted(Version.VERSION3,
                "example.com/owid/api/v3/public-key?x=",
                Instant.parse("2026-09-04T00:00:00Z"));
        assertThrows(OwidException.class,
                () -> PublicKeyFetch.publicKeyUrl(owid, "https"),
                "a domain carrying a path and a query is refused");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                PublicKeyFetch.verify(owid, "https", ALONE).getStatus(),
                "a URL that cannot be built leaves the signature unjudged");
    }

    /**
     * A scheme that does not make an HTTP request is reported as a key that
     * could not be obtained, rather than escaping as a cast failure. Every
     * route into the fetch promises a status, so no route may throw
     * something unchecked past it.
     *
     * <p>The scheme used here has a handler in the JDK which opens no
     * connection at all, so the test costs nothing and reaches nobody. A
     * scheme with no handler takes the same route out, because the refusal
     * to build the URL is reported as the same status.</p>
     */
    @Test
    void aSchemeThatIsNotHttpIsKeyUnavailable() throws OwidException {
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                PublicKeyFetch.verify(
                        KeyFixtures.identifier(), "mailto", ALONE).getStatus(),
                "a scheme that fetches no key leaves the signature unjudged");
    }

    /** The scheme and the OWID are both needed to build a URL. */
    @Test
    void missingValuesAreRefused() {
        assertThrows(OwidException.class,
                () -> PublicKeyFetch.publicKeyUrl(null, "https"),
                "there is no URL without an OWID");
        assertThrows(OwidException.class,
                () -> PublicKeyFetch.publicKeyUrl(
                        KeyFixtures.identifier(), "  "),
                "there is no URL without a scheme");
    }

    /**
     * Builds an OWID with the version, domain and date given and a signature
     * of zeroes, for the cases that are about the URL rather than about the
     * signature. Reading it back is the only way an OWID reaches a caller, so
     * the bytes are written and then parsed.
     */
    private static Owid crafted(Version version, String domain, Instant date)
            throws OwidException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Io.writeByte(buffer, version.asByte());
        Io.writeString(buffer, domain);
        Io.writeDate(buffer, date, version);
        Io.writeByteArray(buffer, new byte[0]);
        Io.writeSignature(buffer, new byte[Owid.SIGNATURE_LENGTH]);
        OwidParseResult result = Owid.parse(buffer.toByteArray());
        assertEquals(OwidParseStatus.PARSED, result.getStatus(),
                "should read back the crafted OWID");
        Owid owid = result.getValue();
        assertNotNull(owid, "a successful read hands back the OWID");
        assertTrue(Arrays.equals(new byte[Owid.SIGNATURE_LENGTH],
                owid.getSignature()),
                "the crafted OWID carries no real signature");
        return owid;
    }
}
