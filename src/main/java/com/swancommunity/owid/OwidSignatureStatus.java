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
 * The outcome of asking whether an OWID signature is genuine.
 *
 * <p>Only two of these say anything about the signature itself. The rest say
 * the question could not be answered, which is a different thing and must
 * never be reported as a forgery. A key that cannot be obtained, a key that
 * cannot be decoded, or a provider that fails leaves the signature unjudged,
 * and a caller acting on "invalid" would reject good identifiers during an
 * outage.</p>
 *
 * <p>That is not hypothetical. On 30 August 2026 the key end points served
 * PEM a strict parser rejects and every offline verification against them
 * failed while the keys and the identifiers were both fine. Reported as
 * {@link #INVALID_KEY} that reads as the operational fault it was, whereas
 * reported as {@link #SIGNATURE_INVALID} it would have read as an
 * attack.</p>
 */
public enum OwidSignatureStatus {

    /** The signature is genuine for this data and this key. */
    SIGNATURE_VALID,

    /**
     * The signature is well formed and does not match, so the data does not
     * belong to the key it claims. This is the only status that means the
     * identifier should be distrusted.
     */
    SIGNATURE_INVALID,

    /**
     * A signature field of the wrong length reached a verification surface
     * directly. Truncation in raw external input is a parse
     * {@link OwidParseStatus#UNEXPECTED_END} or
     * {@link OwidParseStatus#BYTE_COUNT_MISMATCH} instead, because there the
     * envelope never formed.
     *
     * <p>A consumer of this library cannot produce it, because both routes an
     * OWID arrives by settle the signature at the length the version
     * requires. It is kept, and tested from inside the library, because the
     * status is part of the cross language vocabulary and other surfaces can
     * be handed a signature field on its own.</p>
     */
    INVALID_SIGNATURE_LENGTH,

    /**
     * No key was supplied, or the one supplied cannot verify. The signature
     * was never examined.
     */
    KEY_UNAVAILABLE,

    /**
     * Key material arrived but cannot be decoded, imported, or used as the
     * required type. The fault is in the key and not in the identifier.
     */
    INVALID_KEY,

    /**
     * The work required is more than this runtime can hold.
     *
     * <p>Not covered by a test, because reaching it needs an OWID and its
     * chain to approach the two gigabyte limit of a Java array, which cannot
     * be built in a test suite that has to run on an ordinary machine. The
     * path to it is real, being the overflow guard on the serialized length,
     * which raises a distinct exception so this status does not have to be
     * told apart from {@link #VERIFICATION_ERROR} by reading a message.</p>
     */
    IMPLEMENTATION_CAPACITY_EXCEEDED,

    /**
     * The check could not be completed for a reason that is not the
     * identifier's fault, such as a cryptographic provider failing on valid
     * inputs or a field that cannot be encoded for signing.
     */
    VERIFICATION_ERROR
}
