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

/**
 * The byte version of an OWID. Always the first byte of the serialized form.
 *
 * <p>Versions 1 and 2 were deprecated during development of the specification
 * because they used an insecure algorithm or an insufficiently precise time
 * indicator. They remain readable for compatibility with data created by
 * earlier implementations.</p>
 */
public enum Version {

    /**
     * Marker used to indicate an optional OWID that is not present, inside a
     * larger framed byte array.
     *
     * <p>No OWID carries this version, so reading the marker hands back no
     * value and reports {@link OwidParseStatus#ABSENT_NODE}, being the
     * absence of a node rather than a fault. Reading one frame out of
     * something longer the marker is consumed, so a caller steps over the
     * absent node and reads the frame after it.</p>
     */
    EMPTY(0),

    /**
     * Deprecated. Stored the date as a two byte big endian count of hours
     * elapsed since the base date.
     */
    VERSION1(1),

    /**
     * Deprecated. Stored the date as a four byte little endian count of
     * minutes elapsed since the base date.
     */
    VERSION2(2),

    /** The current version. The wire format is identical to version 2. */
    VERSION3(3);

    private final int value;

    Version(int value) {
        this.value = value;
    }

    /**
     * Returns the version as the byte written to the serialized form.
     *
     * @return the version byte
     */
    public byte asByte() {
        return (byte) value;
    }

    /**
     * Returns the default version for new OWIDs, which is the current
     * version.
     *
     * @return {@link #VERSION3}
     */
    public static Version current() {
        return VERSION3;
    }

    /**
     * Maps a byte to the matching version, or null when the byte is not a
     * known version. Reading a version the implementation does not know is
     * an ordinary outcome for data that arrived from outside, so it is
     * answered rather than thrown, and the caller reports it as
     * {@link OwidParseStatus#UNSUPPORTED_VERSION}.
     */
    static Version forByte(int value) {
        int unsigned = value & 0xFF;
        for (Version version : values()) {
            if (version.value == unsigned) {
                return version;
            }
        }
        return null;
    }
}
