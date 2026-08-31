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
 * Checked exception raised when creating, serializing, signing or verifying
 * OWIDs fails. The message describes the cause and, where relevant, the
 * underlying exception is set as the cause.
 *
 * <p>Reading a serialized OWID does not raise this. Data that arrived from
 * outside is expected to be malformed sometimes, so
 * {@link Owid#parse(String)} and {@link Owid#parse(byte[])} report
 * an {@link OwidParseStatus} instead. What remains here is the caller's own
 * mistakes, such as an invalid creator domain or a field that cannot be
 * serialized, and failures of the cryptography.</p>
 */
public class OwidException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new exception with the message provided.
     *
     * @param message description of the failure
     */
    public OwidException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the message and underlying cause provided.
     *
     * @param message description of the failure
     * @param cause   the underlying exception that triggered this one
     */
    public OwidException(String message, Throwable cause) {
        super(message, cause);
    }
}
