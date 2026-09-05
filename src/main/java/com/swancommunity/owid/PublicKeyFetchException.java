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
 * Raised when the public key of a creator could not be obtained.
 *
 * <p>The status to report is decided where the failure happens and carried
 * here, so a caller never has to read message text to tell an outage from a
 * signature that does not match. The status is never
 * {@link OwidSignatureStatus#SIGNATURE_INVALID}, because a key that never
 * arrived leaves the signature unexamined.</p>
 *
 * <p>The Go port answers the same need with {@code KeyFetchError}.</p>
 */
public class PublicKeyFetchException extends OwidException {

    private static final long serialVersionUID = 1L;

    private final OwidSignatureStatus status;
    private final String domain;
    private final int statusCode;

    /**
     * Creates a new exception describing a key that could not be obtained.
     *
     * @param message    description of the failure
     * @param status     the status to report for the identifier whose key
     *                   this was
     * @param domain     the creator domain the key was asked of
     * @param statusCode the HTTP response code, or zero where no response
     *                   arrived at all
     * @param cause      the underlying failure, or null where there was none
     */
    public PublicKeyFetchException(String message,
            OwidSignatureStatus status, String domain, int statusCode,
            Throwable cause) {
        super(message, cause);
        this.status = status;
        this.domain = domain;
        this.statusCode = statusCode;
    }

    /**
     * Returns the status to report for the identifier whose key could not be
     * obtained.
     *
     * @return the signature status, which says the question was not answered
     */
    public OwidSignatureStatus getStatus() {
        return status;
    }

    /**
     * Returns the creator domain the key was asked of.
     *
     * @return the domain
     */
    public String getDomain() {
        return domain;
    }

    /**
     * Returns the HTTP response code, or zero where no response arrived at
     * all.
     *
     * @return the response code, or zero
     */
    public int getStatusCode() {
        return statusCode;
    }
}
