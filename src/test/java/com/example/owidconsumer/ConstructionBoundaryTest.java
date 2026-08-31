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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.swancommunity.owid.Creator;
import com.swancommunity.owid.Crypto;
import com.swancommunity.owid.Owid;
import com.swancommunity.owid.OwidException;
import com.swancommunity.owid.OwidParseResult;
import com.swancommunity.owid.OwidParseStatus;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import org.junit.jupiter.api.Test;

/**
 * What a library user outside the OWID package can and cannot do.
 *
 * <p>This test lives in another package on purpose. The tests that sit beside
 * the library share its package, so the compiler lets them reach things a
 * consumer cannot, and a construction boundary asserted from inside would
 * measure nothing. Everything here goes through the same public surface a
 * consumer compiles against.</p>
 */
class ConstructionBoundaryTest {

    /**
     * There is no public constructor, so no caller can name one. This is the
     * compiler's own rule rather than a check made at run time, and the
     * reflective attempt below shows the runtime refuses it as well.
     */
    @Test
    void owidHasNoPublicConstructor() {
        assertEquals(0, Owid.class.getConstructors().length,
                "an OWID should not be constructible by a caller");
        for (Constructor<?> constructor
                : Owid.class.getDeclaredConstructors()) {
            int modifiers = constructor.getModifiers();
            assertTrue(Modifier.isPublic(modifiers) == false
                            && Modifier.isProtected(modifiers) == false,
                    "every OWID constructor should be package private");
        }
    }

    /**
     * The runtime refuses the constructor as well, so the boundary is not
     * only a compile time one. Reflection with setAccessible could still
     * reach it, which is true of every package private member in Java and is
     * the honest limit of the mechanism.
     */
    @Test
    void reflectiveConstructionIsRefused() {
        for (Constructor<?> constructor
                : Owid.class.getDeclaredConstructors()) {
            Object[] arguments = new Object[constructor.getParameterCount()];
            assertThrows(IllegalAccessException.class,
                    () -> constructor.newInstance(arguments),
                    "the runtime should refuse a package private constructor");
        }
    }

    /** No field can be set or rebound from outside. */
    @Test
    void owidHasNoPublicMutation() {
        for (Method method : Owid.class.getMethods()) {
            assertTrue(method.getName().startsWith("set") == false,
                    "an OWID should have no setter, but has "
                            + method.getName());
        }
        for (Field field : Owid.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())) {
                continue;
            }
            assertTrue(Modifier.isPrivate(field.getModifiers()),
                    "every OWID field should be private, but "
                            + field.getName() + " is not");
            assertTrue(Modifier.isFinal(field.getModifiers()),
                    "every OWID field should be final, but "
                            + field.getName() + " is not");
        }
    }

    /**
     * There is no public way to sign an OWID either, because with no way to
     * obtain an unsigned one there is nothing outside to sign, and signing a
     * parsed one again would replace the signature its fields were read with.
     */
    @Test
    void creatorHasNoPublicSigningOfAnOwid() {
        for (Method method : Creator.class.getMethods()) {
            if (method.getName().startsWith("sign") == false) {
                continue;
            }
            fail("a creator should not sign a caller's OWID, but exposes "
                    + method.getName());
        }
    }

    /**
     * Writing into a byte array a caller was handed does not alter the OWID,
     * because a Java array is mutable and the OWID hands out copies.
     */
    @Test
    void writingIntoReturnedArraysDoesNotAlterTheOwid() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);
        Owid owid = creator.createBytes(new byte[] {1, 2, 3});
        byte[] encoded = owid.asByteArray();

        byte[] payload = owid.getPayload();
        byte[] signature = owid.getSignature();
        payload[0] = 99;
        signature[0] ^= 0xFF;

        assertArrayEquals(new byte[] {1, 2, 3}, owid.getPayload(),
                "the payload should be unchanged");
        assertNotEquals(99, owid.getPayload()[0],
                "writing into the copy should not reach the OWID");
        assertArrayEquals(encoded, owid.asByteArray(),
                "the OWID should serialise to the same bytes");
        assertTrue(owid.verifyWithCrypto(crypto, Collections.<Owid>emptyList()),
                "the OWID should still verify");
    }

    /**
     * A library user can still do everything the old surface allowed, by the
     * new route. Creating, chaining, serialising, reading back and verifying
     * all work without ever naming a constructor.
     */
    @Test
    void aLibraryUserCanStillDoEverything() throws OwidException {
        Crypto crypto = Crypto.generate();
        Creator creator = Creator.create("example.com", crypto);

        Owid root = creator.createString("root");
        Owid party = creator.createBytes(
                "party".getBytes(StandardCharsets.UTF_8),
                Collections.singletonList(root));

        OwidParseResult result = Owid.parse(party.asBase64());
        assertEquals(OwidParseStatus.PARSED, result.getStatus(),
                "the created OWID should read back");
        Owid copy = result.getValue();

        assertEquals(party, copy, "should read back an equal OWID");
        assertTrue(copy.verifyWithPublicKey(crypto.publicKeyPem(),
                        Collections.singletonList(root)),
                "should verify with the same others");
        assertEquals("party", copy.payloadAsString(),
                "should carry the payload it was created with");
    }
}
