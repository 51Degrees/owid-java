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
 * What a read of a serialized OWID produced, and why.
 *
 * <p>Every read reports the same three facts, so a caller never has to infer
 * one of them from another. Whether it worked is
 * {@link #isSuccess()}, the OWID is {@link #getValue()} and is present only
 * on success, and the reason is {@link #getStatus()} either way.</p>
 *
 * <p>The three move together. When {@link #isSuccess()} is true the value is
 * not null and the status is {@link OwidParseStatus#PARSED}, and when it is
 * false the value is null and the status names one of the expected
 * problems, or says the bytes were the marker for an absent node.</p>
 *
 * <p>A result carries no text taken from the input. The bytes came from
 * outside, so putting them in a message would mean logging whatever an
 * untrusted sender chose to send.</p>
 */
public final class OwidParseResult {

    private final Owid value;

    private final OwidParseStatus status;

    private final int byteCount;

    private OwidParseResult(Owid value, OwidParseStatus status,
            int byteCount) {
        this.value = value;
        this.status = status;
        this.byteCount = byteCount;
    }

    /**
     * The result of a read that produced the OWID given, occupying the number
     * of bytes given.
     */
    static OwidParseResult parsed(Owid value, int byteCount) {
        return new OwidParseResult(value, OwidParseStatus.PARSED, byteCount);
    }

    /** The result of a read that failed for the reason given. */
    static OwidParseResult failed(OwidParseStatus status) {
        return new OwidParseResult(null, status, 0);
    }

    /**
     * The result of reading the marker for an absent node, which hands back
     * no OWID but does occupy the bytes given, so a caller reading one frame
     * after another steps over the absent node and reads the one after it.
     */
    static OwidParseResult absentNode(int byteCount) {
        return new OwidParseResult(
                null, OwidParseStatus.ABSENT_NODE, byteCount);
    }

    /**
     * Whether the bytes were a complete, structurally valid OWID. This says
     * nothing about whether the signature is genuine, which is a separate
     * question answered by
     * {@link Owid#verify(Crypto, java.util.List)}.
     *
     * @return true when the read produced an OWID
     */
    public boolean isSuccess() {
        return status == OwidParseStatus.PARSED;
    }

    /**
     * The OWID that was read, or null when there was none. Callers should
     * test {@link #isSuccess()} first rather than testing this for null,
     * because the status also says which of the expected problems it was, or
     * that the bytes were the marker for an absent node.
     *
     * @return the OWID on success, otherwise null
     */
    public Owid getValue() {
        return value;
    }

    /**
     * Why the read succeeded or failed.
     *
     * @return {@link OwidParseStatus#PARSED} on success, otherwise the
     *         specific reason
     */
    public OwidParseStatus getStatus() {
        return status;
    }

    /**
     * How many bytes the read occupied.
     *
     * <p>This is what a caller reading one frame after another needs in order
     * to find the next one. {@link Owid#parse(java.nio.ByteBuffer)} moves the
     * buffer along by this much itself, so a caller using that surface does
     * not have to. On a successful whole buffer read this is the length of
     * the buffer, because there the envelope is the whole of it.</p>
     *
     * <p>Three cases. The length of the envelope on success, one byte for
     * {@link OwidParseStatus#ABSENT_NODE} so that a caller steps over the
     * marker and reads the frame after it, and zero for every failure, since
     * a read that failed consumed nothing and left the caller where it
     * started.</p>
     *
     * @return the bytes the read occupied, or zero
     */
    public int getByteCount() {
        return byteCount;
    }

    /**
     * The status name on its own. The input is deliberately absent, because
     * a parse failure is often logged and the bytes came from outside.
     *
     * @return the status name
     */
    @Override
    public String toString() {
        return status.name();
    }
}
