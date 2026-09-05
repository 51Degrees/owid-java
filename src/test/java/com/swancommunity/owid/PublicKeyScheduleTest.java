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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.swancommunity.owid.KeyFixtures.ScheduledKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Choosing the key that signed an identifier out of the schedule a creator
 * published.
 *
 * <p>This is where every other port went wrong, each in its own way, so the
 * rule is checked against the real published 51d.es schedule and a real
 * identifier rather than against keys made up for the occasion.</p>
 */
class PublicKeyScheduleTest {

    /** The week the fixture identifier was signed in. */
    private static final Instant WEEK_OF_THE_IDENTIFIER =
            Instant.parse("2026-08-31T00:00:00Z");

    /** No other OWIDs were covered by the signature on the fixture. */
    private static final List<Owid> ALONE = Collections.emptyList();

    /**
     * The genuine identifier verifies against the key the published schedule
     * says was in force on the day the identifier was signed. This is the
     * fixed point the rest of the dated key work is measured against,
     * because it uses no HTTP and no URL building at all.
     */
    @Test
    void genuineIdentifierVerifiesAgainstTheKeyInForceOnItsDate()
            throws OwidException {
        Owid owid = KeyFixtures.identifier();
        assertEquals(KeyFixtures.IDENTIFIER_DOMAIN, owid.getDomain(),
                "the fixture names the creator domain");
        assertEquals(Instant.parse("2026-09-04T00:00:00Z"), owid.getDate(),
                "the fixture was signed on 4 September 2026");
        DatedPublicKey key = KeyFixtures.schedule().keyFor(owid);
        assertNotNull(key, "the schedule covers the date");
        assertEquals(WEEK_OF_THE_IDENTIFIER, key.getStartsAt(),
                "the week beginning 31 August covers 4 September");
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                owid.verify(key.getPublicKeyPem(), ALONE).getStatus(),
                "should verify against the key that signed it");
    }

    /**
     * The schedule answers the same question in one call, which is what a
     * caller holding a published schedule uses.
     */
    @Test
    void scheduleVerifiesTheGenuineIdentifier() throws OwidException {
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                KeyFixtures.schedule()
                        .verify(KeyFixtures.identifier(), ALONE).getStatus(),
                "should pick the signing key and verify in one call");
    }

    /**
     * The key in force in the following week does not verify the identifier, which is
     * the whole reason the date has to be part of the question. Keys rotate
     * weekly, so the key in force when an identifier is checked is not the
     * key that signed it unless the check happens in the same week.
     */
    @Test
    void aLaterWeeksKeyDoesNotVerifyAnEarlierWeeksIdentifier()
            throws OwidException {
        Owid owid = KeyFixtures.identifier();
        DatedPublicKey later = KeyFixtures.schedule()
                .keyInForce(KeyEndPoint.REQUEST_MOMENT);
        assertNotNull(later, "the schedule covers the moment of the request");
        assertTrue(later.getStartsAt().isAfter(owid.getDate()),
                "the key in force in the following week starts after the identifier "
                        + "was signed");
        assertEquals(OwidSignatureStatus.SIGNATURE_INVALID,
                owid.verify(later.getPublicKeyPem(), ALONE).getStatus(),
                "a later week's key should not verify an earlier week's "
                        + "identifier");
    }

    /**
     * The last key by start is not the key in force. A creator publishes its
     * schedule ahead of time, so the last key is one whose period has not
     * begun, and serving it where the current key was meant reports every
     * genuine identifier as not matching. That is the fault the .NET port
     * carried in its answer to a request with no date, and it is kept out of
     * this port by holding the two questions apart.
     */
    @Test
    void theLastKeyIsNotTheKeyInForce() throws OwidException {
        Instant now = Instant.now();
        PublicKeySchedule schedule = PublicKeySchedule.of(Arrays.asList(
                DatedPublicKey.of(now.minus(Duration.ofDays(7)),
                        KeyFixtures.scheduledKeys().get(0).pem()),
                DatedPublicKey.of(now.plus(Duration.ofDays(7)),
                        KeyFixtures.scheduledKeys().get(1).pem()),
                DatedPublicKey.of(now.plus(Duration.ofDays(14)),
                        KeyFixtures.scheduledKeys().get(2).pem())));
        assertEquals(now.plus(Duration.ofDays(14)),
                schedule.last().getStartsAt(),
                "the last key is the one with the latest start");
        assertEquals(now.minus(Duration.ofDays(7)),
                schedule.current().getStartsAt(),
                "the key in force now is the one that has started");
    }

    /**
     * The shape that broke the .NET port. Thirteen of the published keys were
     * generated in one batch on 1 September 2026 and cover the weeks from 7
     * September to 30 November, so on 4 September the newest key that had
     * already been generated was one that had not started yet.
     *
     * <p>Selecting on the generation moment picks that unstarted key and
     * reports a genuine identifier as not matching. Selecting on the start,
     * which is what this library does, picks the week beginning 31 August and
     * the identifier verifies.</p>
     */
    @Test
    void selectionIgnoresTheMomentTheKeysWereGenerated() throws OwidException {
        Owid owid = KeyFixtures.identifier();
        List<ScheduledKey> published = KeyFixtures.scheduledKeys();

        ScheduledKey newestGenerated = null;
        int sharingTheBatch = 0;
        for (ScheduledKey key : published) {
            if (key.created().isAfter(owid.getDate())) {
                continue;
            }
            if (newestGenerated == null
                    || key.created().isAfter(newestGenerated.created())) {
                newestGenerated = key;
            }
        }
        assertNotNull(newestGenerated, "keys were generated before the date");
        for (ScheduledKey key : published) {
            if (key.created().equals(newestGenerated.created())) {
                sharingTheBatch++;
            }
        }
        assertEquals(13, sharingTheBatch,
                "thirteen keys share the generation moment of 1 September");
        assertTrue(newestGenerated.startsAt().isAfter(owid.getDate()),
                "the newest generated key had not started when the "
                        + "identifier was signed");
        assertEquals(OwidSignatureStatus.SIGNATURE_INVALID,
                owid.verify(newestGenerated.pem(), ALONE).getStatus(),
                "selecting on the generation moment reports a genuine "
                        + "identifier as not matching");

        DatedPublicKey chosen = KeyFixtures.schedule().keyFor(owid);
        assertNotNull(chosen, "the schedule covers the date");
        assertEquals(WEEK_OF_THE_IDENTIFIER, chosen.getStartsAt(),
                "selecting on the start picks the week that was running");
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                owid.verify(chosen.getPublicKeyPem(), ALONE).getStatus(),
                "selecting on the start verifies the genuine identifier");
    }

    /**
     * A key is in force from the moment it starts until the moment the next
     * key starts, so the boundary belongs to the key that is starting.
     */
    @Test
    void aKeyIsInForceFromItsStartUntilTheNextStart() throws OwidException {
        PublicKeySchedule schedule = KeyFixtures.schedule();
        List<DatedPublicKey> keys = schedule.getKeys();
        for (int i = 1; i < keys.size(); i++) {
            DatedPublicKey previous = keys.get(i - 1);
            DatedPublicKey key = keys.get(i);
            Instant start = key.getStartsAt();
            assertEquals(key.getStartsAt(),
                    schedule.keyInForce(start).getStartsAt(),
                    "the start belongs to the key that is starting");
            assertEquals(previous.getStartsAt(),
                    schedule.keyInForce(
                            start.minus(Duration.ofMinutes(1))).getStartsAt(),
                    "the minute before the start belongs to the key before");
            assertEquals(key.getStartsAt(),
                    schedule.keyInForce(
                            start.plus(Duration.ofDays(6))).getStartsAt(),
                    "the rest of the week belongs to the key that started");
        }
    }

    /** The keys are held oldest start first however the keys arrive. */
    @Test
    void keysMayArriveInAnyOrder() throws OwidException {
        List<DatedPublicKey> forwards = KeyFixtures.schedule().getKeys();
        List<DatedPublicKey> backwards =
                new ArrayList<DatedPublicKey>(forwards);
        Collections.reverse(backwards);
        PublicKeySchedule reversed = PublicKeySchedule.of(backwards);
        assertEquals(forwards.size(), reversed.size(),
                "the same keys are held");
        for (int i = 0; i < forwards.size(); i++) {
            assertEquals(forwards.get(i).getStartsAt(),
                    reversed.getKeys().get(i).getStartsAt(),
                    "the keys are held oldest start first");
        }
        assertEquals(OwidSignatureStatus.SIGNATURE_VALID,
                reversed.verify(KeyFixtures.identifier(), ALONE).getStatus(),
                "the order the keys arrived in changes nothing");
    }

    /**
     * A date the schedule does not reach has no key, and that is reported as
     * a question left unanswered rather than as a signature that does not
     * match.
     */
    @Test
    void aDateBeforeTheScheduleHasNoKey() throws OwidException {
        PublicKeySchedule schedule = KeyFixtures.schedule();
        Instant first = schedule.getKeys().get(0).getStartsAt();
        assertNull(schedule.keyInForce(first.minus(Duration.ofMinutes(1))),
                "no key had started a minute before the first start");
        assertNull(schedule.keyInForce(Io.baseDate()),
                "no key had started at the base date");
    }

    /** An empty schedule answers with no key rather than failing. */
    @Test
    void anEmptyScheduleHasNoKey() throws OwidException {
        PublicKeySchedule schedule = PublicKeySchedule.of(
                Collections.<DatedPublicKey>emptyList());
        assertEquals(0, schedule.size(), "the schedule holds no keys");
        assertNull(schedule.last(), "there is no last key");
        assertNull(schedule.current(), "there is no key in force");
        assertNull(schedule.keyInForce(Instant.now()),
                "no key was in force");
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                schedule.verify(KeyFixtures.identifier(), ALONE).getStatus(),
                "no key means the signature was never examined");
    }

    /** A missing OWID leaves the signature unjudged rather than failing. */
    @Test
    void aMissingOwidIsKeyUnavailable() throws OwidException {
        assertEquals(OwidSignatureStatus.KEY_UNAVAILABLE,
                KeyFixtures.schedule().verify(null, ALONE).getStatus(),
                "there is nothing to find a key for");
    }

    /**
     * Where two keys share a start, the one supplied first wins, as the
     * cloud and the .NET port settle it, so the answer is the same in every
     * port rather than left to the order a map or a fetch happened to
     * produce.
     */
    @Test
    void twoKeysSharingAStartAreSettledInFavourOfTheFirstSupplied()
            throws OwidException {
        Instant start = Instant.parse("2026-08-31T00:00:00Z");
        DatedPublicKey first = DatedPublicKey.of(start,
                KeyFixtures.scheduledKeys().get(0).pem());
        DatedPublicKey second = DatedPublicKey.of(start,
                KeyFixtures.scheduledKeys().get(1).pem());
        PublicKeySchedule schedule = PublicKeySchedule.of(
                Arrays.asList(first, second));
        assertEquals(first.getPublicKeyPem(),
                schedule.keyInForce(start).getPublicKeyPem(),
                "the key supplied first wins the shared start");
        assertEquals(first.getPublicKeyPem(),
                schedule.keyInForce(start.plus(Duration.ofDays(1)))
                        .getPublicKeyPem(),
                "and keeps winning for the rest of the period");
    }

    /** The schedule and its keys refuse the values a caller cannot mean. */
    @Test
    void missingValuesAreRefused() {
        assertThrows(OwidException.class,
                () -> DatedPublicKey.of(null, "-----BEGIN PUBLIC KEY-----"),
                "a key with no start cannot be placed in a schedule");
        assertThrows(OwidException.class,
                () -> DatedPublicKey.of(Instant.now(), "  "),
                "a key with no material cannot verify anything");
        assertThrows(OwidException.class,
                () -> PublicKeySchedule.of(null),
                "there is no schedule without keys to hold");
    }

    /** The list of keys handed out cannot be changed by a caller. */
    @Test
    void theKeysHandedOutCannotBeChanged() throws OwidException {
        final List<DatedPublicKey> keys = KeyFixtures.schedule().getKeys();
        assertThrows(UnsupportedOperationException.class,
                () -> keys.clear(),
                "the schedule is read only once built");
    }
}
