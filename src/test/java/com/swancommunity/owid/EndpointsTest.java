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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Unit tests for the well known end point helpers. */
class EndpointsTest {

    private static Creator newCreator() throws OwidException {
        return Creator.create("example.com", Crypto.generate());
    }

    @Test
    void paths() {
        assertEquals("/owid/api/v3/creator",
                Endpoints.creatorPath(Version.VERSION3),
                "should match the creator path");
        assertEquals("/owid/api/v3/public-key",
                Endpoints.publicKeyPath(Version.VERSION3),
                "should match the public key path");
    }

    @Test
    void creatorResponseFields() throws OwidException {
        Creator creator = newCreator();
        String body = Endpoints.creatorResponse(creator, "Example Org",
                "https://example.com/terms");
        assertTrue(body.contains("\"domain\":\"example.com\""),
                "should contain the domain");
        assertTrue(body.contains("\"name\":\"Example Org\""),
                "should contain the name");
        assertTrue(body.contains("publicKeySPKI"),
                "should use the specification field names");
        assertTrue(body.contains("BEGIN PUBLIC KEY"),
                "should embed the public key PEM");
        assertTrue(body.contains("\"contractURL\":\"https://example.com/terms\""),
                "should contain the contract URL");
    }

    @Test
    void publicKeyResponseFormats() throws OwidException {
        Creator creator = newCreator();
        for (String format : new String[] {"spki", "pkcs"}) {
            String body = Endpoints.publicKeyResponse(creator, format);
            assertTrue(body.contains("BEGIN PUBLIC KEY"),
                    "should return the PEM for format " + format);
        }
        assertThrows(OwidException.class,
                () -> Endpoints.publicKeyResponse(creator, "other"),
                "should reject an unknown format");
    }
}
