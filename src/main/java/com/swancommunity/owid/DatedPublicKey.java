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

/**
 * One signing public key together with the moment the key came into force.
 *
 * <p>A creator that rotates its signing key publishes a schedule of these,
 * and an OWID is signed by whichever key had started by the date the OWID
 * carries. The only date held here is that start, because the start is the
 * only date the selection rule uses.</p>
 *
 * <p>Nothing records when the key material was generated, and that omission
 * is deliberate. Keys are commonly generated in a batch weeks ahead of the
 * weeks the keys cover, so several keys share one generation moment while
 * starting on different days. Choosing by the generation moment then picks a
 * key that has not started yet and reports a genuine identifier as not
 * matching, which is the defect the .NET port carried. Holding no such field
 * means no caller of this library can select by the field.</p>
 */
public final class DatedPublicKey {

    private final Instant startsAt;
    private final String publicKeyPem;

    private DatedPublicKey(Instant startsAt, String publicKeyPem) {
        this.startsAt = startsAt;
        this.publicKeyPem = publicKeyPem;
    }

    /**
     * Creates a key that came into force at the moment given.
     *
     * @param startsAt     the moment the key came into force, in UTC
     * @param publicKeyPem the public key in Subject Public Key Info PEM form
     * @return the dated key
     * @throws OwidException if the start is missing, or the PEM is missing,
     *                       empty or whitespace
     */
    public static DatedPublicKey of(Instant startsAt, String publicKeyPem)
            throws OwidException {
        if (startsAt == null) {
            throw new OwidException("the date the key starts is missing");
        }
        if (publicKeyPem == null || publicKeyPem.trim().isEmpty()) {
            throw new OwidException("public key PEM is empty");
        }
        return new DatedPublicKey(startsAt, publicKeyPem);
    }

    /**
     * Returns the moment the key came into force. An OWID dated at or after
     * this moment, and before the start of the key that follows, was signed
     * by this key.
     *
     * @return the start of the period the key covers
     */
    public Instant getStartsAt() {
        return startsAt;
    }

    /**
     * Returns the public key in Subject Public Key Info PEM form, as the
     * public key end point serves the key.
     *
     * @return the public key PEM
     */
    public String getPublicKeyPem() {
        return publicKeyPem;
    }

    @Override
    public String toString() {
        return "key starting " + startsAt;
    }
}
