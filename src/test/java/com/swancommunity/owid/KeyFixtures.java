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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * The genuine 51Did identifier and the published 51d.es key schedule the
 * dated key tests are measured against.
 *
 * <p>Both fixtures are real. The identifier was created by the 51Degrees
 * cloud on 4 September 2026 for the creator domain 51d.es, and the schedule
 * is the thirty weekly keys the public key end point served for that domain
 * from 11 May to 30 November 2026. Both are public and carry no secret.</p>
 *
 * <p>The schedule holds the moment each key was generated as well as the date
 * each key came into force, which the library itself does not, so that a test
 * can show what selecting by the generation moment would have picked. Thirteen
 * of the keys were generated in one batch and share that moment while starting
 * on thirteen different weeks.</p>
 */
final class KeyFixtures {

    /**
     * The minute count the fixture identifier carries, being
     * 2026-09-04T00:00:00Z counted from 2020-01-01. Written out rather than
     * computed, so that a change to the counting is caught here instead of
     * being carried into the expected URL as well.
     */
    static final long IDENTIFIER_MINUTES = 3_510_720L;

    /** The creator domain the fixture identifier names. */
    static final String IDENTIFIER_DOMAIN = "51d.es";

    private KeyFixtures() {
    }

    /** One entry of the published schedule. */
    static final class ScheduledKey {

        private final Instant startsAt;
        private final Instant created;
        private final String pem;

        ScheduledKey(Instant startsAt, Instant created, String pem) {
            this.startsAt = startsAt;
            this.created = created;
            this.pem = pem;
        }

        /** The date the key came into force, which selection uses. */
        Instant startsAt() {
            return startsAt;
        }

        /**
         * The moment the key material was generated, which selection must
         * not use. Held only so a test can show what using it would pick.
         */
        Instant created() {
            return created;
        }

        /** The key as the end point serves it. */
        String pem() {
            return pem;
        }
    }

    /** The genuine identifier from the fixture. */
    static Owid identifier() {
        List<String> value = records("/identifier.txt");
        assertEquals(1, value.size(), "the fixture holds one identifier");
        OwidParseResult result = Owid.parse(value.get(0));
        assertEquals(OwidParseStatus.PARSED, result.getStatus(),
                "should read the genuine identifier");
        Owid owid = result.getValue();
        assertNotNull(owid, "a successful read hands back the identifier");
        return owid;
    }

    /** The published schedule from the fixture, oldest start first. */
    static List<ScheduledKey> scheduledKeys() {
        List<ScheduledKey> keys = new ArrayList<ScheduledKey>();
        for (String record : records("/public-key-schedule.txt")) {
            String[] fields = record.split(" ");
            assertEquals(3, fields.length,
                    "a record is a start, a generation moment and a key");
            keys.add(new ScheduledKey(
                    Instant.parse(fields[0]),
                    Instant.parse(fields[1]),
                    pem(fields[2])));
        }
        return keys;
    }

    /** The published schedule as the library holds it. */
    static PublicKeySchedule schedule() throws OwidException {
        List<DatedPublicKey> keys = new ArrayList<DatedPublicKey>();
        for (ScheduledKey key : scheduledKeys()) {
            keys.add(DatedPublicKey.of(key.startsAt(), key.pem()));
        }
        return PublicKeySchedule.of(keys);
    }

    /**
     * Wraps the base 64 body of a key back into the PEM the end point
     * serves, being sixty four characters to a line.
     */
    private static String pem(String body) {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < body.length(); i += 64) {
            pem.append(body, i, Math.min(i + 64, body.length())).append('\n');
        }
        pem.append("-----END PUBLIC KEY-----\n");
        return pem.toString();
    }

    /**
     * Reads a fixture from the test resources, dropping the comment lines
     * that describe it and any blank lines, and returning the records that
     * remain.
     */
    private static List<String> records(String resource) {
        List<String> lines = new ArrayList<String>();
        InputStream stream = KeyFixtures.class.getResourceAsStream(resource);
        assertNotNull(stream, "should find the fixture " + resource);
        try {
            try {
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(stream,
                                StandardCharsets.UTF_8));
                String line = reader.readLine();
                while (line != null) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty() == false
                            && trimmed.startsWith("#") == false) {
                        lines.add(trimmed);
                    }
                    line = reader.readLine();
                }
            } finally {
                stream.close();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return lines;
    }
}
