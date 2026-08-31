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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Assertions over a parse result, used everywhere a test reads an OWID.
 *
 * <p>Each one checks all three facts a result reports rather than only the
 * one the test is interested in, so no test can pass while the result is
 * internally inconsistent.</p>
 */
final class ParseAssert {

    private ParseAssert() {
    }

    /**
     * Asserts the read worked and returns the OWID, checking that success,
     * the value and the status agree.
     */
    static Owid parsed(OwidParseResult result) {
        assertNotNull(result, "a read should always report a result");
        assertTrue(result.isSuccess(),
                "should have read an OWID but reported " + result.getStatus());
        assertEquals(OwidParseStatus.PARSED, result.getStatus(),
                "a successful read should report PARSED");
        assertNotNull(result.getValue(),
                "a successful read should hand back the OWID");
        assertTrue(result.getByteCount() > 0,
                "a successful read should report the bytes it consumed");
        return result.getValue();
    }

    /**
     * Asserts the read failed for the reason given, and that nothing was
     * handed back with it.
     */
    static void failed(OwidParseResult result, OwidParseStatus expected) {
        assertNotNull(result, "a read should always report a result");
        assertFalse(result.isSuccess(),
                "should have refused the input but reported success");
        assertEquals(expected, result.getStatus(),
                "should report the reason the input is not an OWID");
        assertNull(result.getValue(),
                "a failed read should hand back no OWID");
        // The framed read moves the buffer on by this much, so a failure
        // reporting anything other than nothing would leave a caller part way
        // through a frame it could not reason about.
        assertEquals(0, result.getByteCount(),
                "a failed read should report consuming nothing");
    }

    /**
     * Asserts the bytes were the marker for an absent node, that nothing was
     * handed back for it, and that it occupied the single byte a caller has
     * to step over to reach the next frame.
     */
    static void absentNode(OwidParseResult result) {
        assertNotNull(result, "a read should always report a result");
        assertFalse(result.isSuccess(),
                "the marker for an absent node is not an OWID");
        assertEquals(OwidParseStatus.ABSENT_NODE, result.getStatus(),
                "should report the absence of a node");
        assertNull(result.getValue(),
                "the marker should hand back no OWID");
        assertEquals(1, result.getByteCount(),
                "the marker should occupy the one byte it is");
    }
}
