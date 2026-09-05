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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * The signing public keys a creator has published, held so that the key which
 * was in force at any date can be found.
 *
 * <p>Creators rotate weekly, so the key that is current when an identifier is
 * checked is not the key that signed the identifier unless the check happens
 * in the same week. Verifying anything older than a few days means choosing
 * the right key out of the schedule, and this class holds the rule for that
 * choice in one place so every caller makes the same choice.</p>
 *
 * <p>The rule is the one the cloud itself applies, being the latest key whose
 * start is at or before the date asked about. Keys are generated in batches,
 * often many weeks ahead of the weeks the keys cover, so the moment key
 * material was generated says nothing about which key signed anything and is
 * not held here at all. Selecting on a generation moment picks a key that has
 * not started yet and reports a genuine identifier as not matching, which is
 * what the .NET port did before that port was fixed.</p>
 *
 * <p>A date the schedule does not reach, being one earlier than the first
 * start, has no key. That answer is reported as
 * {@link OwidSignatureStatus#KEY_UNAVAILABLE} rather than as a signature that
 * does not match, because with no key the signature was never examined.</p>
 */
public final class PublicKeySchedule {

    private final List<DatedPublicKey> keys;

    private PublicKeySchedule(List<DatedPublicKey> keys) {
        this.keys = keys;
    }

    /**
     * Creates a schedule over the keys provided. The keys may arrive in any
     * order and are held oldest start first.
     *
     * <p>Where two keys share a start, the one supplied first wins, which is
     * how the 51Degrees cloud and the .NET port settle it. A creator does
     * not publish two keys for one start, so the case is settled rather
     * than left to chance.</p>
     *
     * @param keys the published keys
     * @return the schedule
     * @throws OwidException if the collection is missing or holds a missing
     *                       key
     */
    public static PublicKeySchedule of(Collection<DatedPublicKey> keys)
            throws OwidException {
        if (keys == null) {
            throw new OwidException("the collection of keys is missing");
        }
        List<DatedPublicKey> ordered = new ArrayList<DatedPublicKey>(keys);
        for (DatedPublicKey key : ordered) {
            if (key == null) {
                throw new OwidException("a key in the schedule is missing");
            }
        }
        Collections.sort(ordered, new Comparator<DatedPublicKey>() {
            @Override
            public int compare(DatedPublicKey left, DatedPublicKey right) {
                return left.getStartsAt().compareTo(right.getStartsAt());
            }
        });
        return new PublicKeySchedule(
                Collections.unmodifiableList(ordered));
    }

    /**
     * Returns the keys held, oldest start first. The list cannot be changed.
     *
     * @return the keys in the schedule
     */
    public List<DatedPublicKey> getKeys() {
        return keys;
    }

    /**
     * Returns the number of keys held.
     *
     * @return the count of keys
     */
    public int size() {
        return keys.size();
    }

    /**
     * Returns the key that was in force at the date given, being the latest
     * key whose start is at or before that date, or null where the schedule
     * begins after the date.
     *
     * @param date the date to find the key for
     * @return the key in force, or null when no key had started
     */
    public DatedPublicKey keyInForce(Instant date) {
        if (date == null) {
            return null;
        }
        for (int i = keys.size() - 1; i >= 0; i--) {
            DatedPublicKey key = keys.get(i);
            if (key.getStartsAt().isAfter(date) == false) {
                // The sort is stable, so keys sharing a start sit in the
                // order supplied, and the first supplied is the answer.
                while (i > 0 && keys.get(i - 1).getStartsAt()
                        .equals(key.getStartsAt())) {
                    i--;
                    key = keys.get(i);
                }
                return key;
            }
        }
        return null;
    }

    /**
     * Returns the key with the latest start, or null where the schedule
     * holds no keys.
     *
     * <p>This is not the key in force now. A creator publishes its schedule
     * ahead of time, so the last key by start is usually one whose period
     * has not begun and which has signed nothing yet. The key in force now
     * is {@link #current()}. Serving the last key where the current one was
     * meant is the same fault as selecting by the generation moment, being
     * a key from a period that has not started, and it is the fault the
     * .NET port carried in its answer to a request that named no date.</p>
     *
     * @return the key with the latest start, or null when there are none
     */
    public DatedPublicKey last() {
        if (keys.isEmpty()) {
            return null;
        }
        return keys.get(keys.size() - 1);
    }

    /**
     * Returns the key in force now, being the latest key whose start is at
     * or before the current moment, or null where no key has started. This
     * is what a creator serves for a request that names no date.
     *
     * @return the key in force now, or null when no key has started
     */
    public DatedPublicKey current() {
        return keyInForce(Instant.now());
    }

    /**
     * Returns the key that signed the OWID, being the key in force at the
     * date the OWID carries, or null where the schedule does not reach back
     * to that date.
     *
     * @param owid the OWID to find the signing key for
     * @return the key in force when the OWID was signed, or null
     */
    public DatedPublicKey keyFor(Owid owid) {
        if (owid == null) {
            return null;
        }
        return keyInForce(owid.getDate());
    }

    /**
     * Asks whether the signature on the OWID is genuine, using the key that
     * was in force when the OWID was signed.
     *
     * @param owid   the OWID to check
     * @param others the other OWIDs that were signed together with this one,
     *               in the same order as when signed
     * @return the outcome of the check, which is
     *         {@link OwidSignatureStatus#KEY_UNAVAILABLE} where the schedule
     *         holds no key for the date
     */
    public OwidVerificationResult verify(Owid owid, List<Owid> others) {
        if (owid == null) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.KEY_UNAVAILABLE);
        }
        DatedPublicKey key = keyFor(owid);
        if (key == null) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.KEY_UNAVAILABLE);
        }
        return owid.verify(key.getPublicKeyPem(), others);
    }
}
