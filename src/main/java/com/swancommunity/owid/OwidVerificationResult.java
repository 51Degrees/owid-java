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
 * What asking whether an OWID signature is genuine produced.
 *
 * <p>{@link #isValid()} is true only when the signature was examined and
 * matched. Everything else is false, but the reasons are not
 * interchangeable, because "does not match" and "could not check" call for
 * different handling and {@link #getStatus()} keeps them apart.</p>
 */
public final class OwidVerificationResult {

    private final OwidSignatureStatus status;

    private OwidVerificationResult(OwidSignatureStatus status) {
        this.status = status;
    }

    /** The result carrying the status given. */
    static OwidVerificationResult of(OwidSignatureStatus status) {
        return new OwidVerificationResult(status);
    }

    /**
     * Whether the signature was examined and found genuine.
     *
     * @return true only for {@link OwidSignatureStatus#SIGNATURE_VALID}
     */
    public boolean isValid() {
        return status == OwidSignatureStatus.SIGNATURE_VALID;
    }

    /**
     * The outcome of the check.
     *
     * @return the signature status
     */
    public OwidSignatureStatus getStatus() {
        return status;
    }

    @Override
    public String toString() {
        return status.name();
    }
}
