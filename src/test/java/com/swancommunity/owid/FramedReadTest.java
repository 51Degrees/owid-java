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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Reading one OWID out of something longer, and leaving what follows alone.
 *
 * <p>The framed read differs from the whole buffer read in one place. A whole
 * buffer has to end where the envelope does, so a byte after the signature
 * belongs to no field, whereas a frame only requires the declared payload and
 * the signature to be present and says nothing about what follows, because
 * what follows is the next frame rather than rubbish.</p>
 */
class FramedReadTest {

    /** The two envelopes used throughout, with payloads that differ. */
    private static final byte[] FIRST =
            Envelope.version3("first.example", 1000L, 3,
                    new byte[] {1, 2, 3}, Envelope.signature());

    private static final byte[] SECOND =
            Envelope.version3("second.example", 2000L, 5,
                    new byte[] {4, 5, 6, 7, 8}, Envelope.signature());

    private static byte[] concatenated() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(FIRST, 0, FIRST.length);
        stream.write(SECOND, 0, SECOND.length);
        return stream.toByteArray();
    }

    /**
     * Two complete envelopes one after the other read as two OWIDs from the
     * same input, and between them they account for every byte.
     */
    @Test
    void twoEnvelopesReadOneAfterTheOther() {
        ByteBuffer buffer = ByteBuffer.wrap(concatenated());

        List<Owid> read = new ArrayList<Owid>();
        while (buffer.hasRemaining()) {
            read.add(ParseAssert.parsed(Owid.parse(buffer)));
        }

        assertEquals(2, read.size(), "should have read both envelopes");
        assertEquals("first.example", read.get(0).getDomain(),
                "should read the first domain");
        assertArrayEquals(new byte[] {1, 2, 3}, read.get(0).getPayload(),
                "should read the first payload");
        assertEquals("second.example", read.get(1).getDomain(),
                "should read the second domain");
        assertArrayEquals(new byte[] {4, 5, 6, 7, 8},
                read.get(1).getPayload(), "should read the second payload");
        assertFalse(buffer.hasRemaining(),
                "the two envelopes should account for every byte");
    }

    /**
     * Each read reports how far it moved, and moves the buffer by exactly
     * that much, so a caller can find the next frame either way.
     */
    @Test
    void eachReadReportsAndConsumesTheEnvelopeLength() {
        ByteBuffer buffer = ByteBuffer.wrap(concatenated());

        OwidParseResult first = Owid.parse(buffer);
        ParseAssert.parsed(first);
        assertEquals(FIRST.length, first.getByteCount(),
                "should report the length of the first envelope");
        assertEquals(FIRST.length, buffer.position(),
                "should move on by the length of the first envelope");

        OwidParseResult second = Owid.parse(buffer);
        ParseAssert.parsed(second);
        assertEquals(SECOND.length, second.getByteCount(),
                "should report the length of the second envelope");
        assertEquals(FIRST.length + SECOND.length, buffer.position(),
                "should move on by the length of the second envelope");
    }

    /**
     * The same two envelopes handed to the whole buffer read are refused,
     * because there nothing else could own the bytes after the first
     * signature.
     */
    @Test
    void theSameTwoEnvelopesAreRefusedByTheWholeBufferRead() {
        ParseAssert.failed(Owid.parse(concatenated()),
                OwidParseStatus.BYTE_COUNT_MISMATCH);
    }

    /**
     * An envelope cut short before its signature is refused, and nothing is
     * consumed, so the caller is left where it started and decides what to do
     * with the bytes itself.
     *
     * <p>The status is a truncation rather than a byte count disagreement,
     * because a caller reading from a source that is still arriving needs to
     * know whether to wait for more bytes or to give up on these.</p>
     */
    @Test
    void truncatedFrameIsRefusedAndConsumesNothing() {
        byte[] cutShort = Arrays.copyOf(FIRST, FIRST.length - 1);
        ByteBuffer buffer = ByteBuffer.wrap(cutShort);

        ParseAssert.failed(Owid.parse(buffer), OwidParseStatus.UNEXPECTED_END);

        assertEquals(0, buffer.position(),
                "a failed read should leave the buffer where it was");
        assertEquals(cutShort.length, buffer.remaining(),
                "a failed read should consume nothing");
    }

    /**
     * A frame that is good but is followed by a bad one leaves the good one
     * read and the buffer sitting at the start of the bad one, which is what
     * lets a caller decide what to do about it.
     */
    @Test
    void aBadFrameLeavesThePositionAtItsStart() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(FIRST, 0, FIRST.length);
        byte[] rubbish = {0x63, 0x63, 0x63};
        stream.write(rubbish, 0, rubbish.length);
        ByteBuffer buffer = ByteBuffer.wrap(stream.toByteArray());

        ParseAssert.parsed(Owid.parse(buffer));
        assertEquals(FIRST.length, buffer.position(),
                "should have read the good frame");

        ParseAssert.failed(Owid.parse(buffer),
                OwidParseStatus.UNSUPPORTED_VERSION);
        assertEquals(FIRST.length, buffer.position(),
                "should leave the buffer at the start of the bad frame");
    }

    /**
     * The framed read reports the same vocabulary as everything else, and it
     * is reachable through the public surface rather than only from inside.
     */
    @Test
    void framedFailuresUseTheSharedVocabulary() {
        // A version this implementation does not know.
        byte[] badVersion = FIRST.clone();
        badVersion[0] = 0x04;
        ParseAssert.failed(Owid.parse(ByteBuffer.wrap(badVersion)),
                OwidParseStatus.UNSUPPORTED_VERSION);

        // A domain that runs past the published maximum before terminating.
        StringBuilder tooLong = new StringBuilder();
        while (tooLong.length() <= Io.MAXIMUM_DOMAIN_LENGTH) {
            tooLong.append('a');
        }
        ParseAssert.failed(
                Owid.parse(ByteBuffer.wrap(
                        Envelope.version3(tooLong.toString(), 1000L, 0,
                                new byte[0], Envelope.signature()))),
                OwidParseStatus.INVALID_DOMAIN_ENCODING);

        // Nothing left to read.
        ParseAssert.failed(Owid.parse(ByteBuffer.wrap(new byte[0])),
                OwidParseStatus.MISSING_INPUT);
        ParseAssert.failed(Owid.parse((ByteBuffer) null),
                OwidParseStatus.MISSING_INPUT);

        // A declaration far larger than the bytes supplied.
        // PayloadLengthTest measures that nothing is sized by it.
        ParseAssert.failed(
                Owid.parse(ByteBuffer.wrap(
                        Envelope.version3(Envelope.DOMAIN, 1000L, 0xFFFFFFFFL,
                                new byte[0], Envelope.signature()))),
                OwidParseStatus.UNEXPECTED_END);

    }

    /**
     * The marker for an absent node hands back no OWID, says so in its own
     * words, and takes the one byte it is, so a caller walking a run of
     * frames can step over a node that is deliberately not there.
     */
    @Test
    void anAbsentNodeIsSteppedOverAndTheNextFrameRead() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        byte[] marker = Owid.emptyByteArray();
        stream.write(marker, 0, marker.length);
        stream.write(FIRST, 0, FIRST.length);
        ByteBuffer buffer = ByteBuffer.wrap(stream.toByteArray());

        ParseAssert.absentNode(Owid.parse(buffer));
        assertEquals(marker.length, buffer.position(),
                "should have stepped over the marker and nothing more");

        Owid owid = ParseAssert.parsed(Owid.parse(buffer));

        assertEquals("first.example", owid.getDomain(),
                "should read the frame that follows the absent node");
        assertFalse(buffer.hasRemaining(),
                "the marker and the frame should account for every byte");
    }

    /**
     * A marker on its own, and a run of them, read as absent nodes rather
     * than as anything wrong.
     */
    @Test
    void aRunOfAbsentNodesReadsOneAtATime() {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] {0, 0, 0});

        int absent = 0;
        while (buffer.hasRemaining()) {
            ParseAssert.absentNode(Owid.parse(buffer));
            absent++;
        }

        assertEquals(3, absent, "should have read three absent nodes");
    }

    /**
     * A frame read from a buffer that starts part way through an array, which
     * is what a caller slicing a larger record hands over.
     */
    @Test
    void aBufferThatStartsPartWayThroughAnArrayReads() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        byte[] prefix = {(byte) 0xEE, (byte) 0xEE};
        stream.write(prefix, 0, prefix.length);
        stream.write(FIRST, 0, FIRST.length);
        ByteBuffer buffer = ByteBuffer.wrap(stream.toByteArray());
        ((Buffer) buffer).position(prefix.length);
        ByteBuffer sliced = buffer.slice();

        Owid owid = ParseAssert.parsed(Owid.parse(sliced));

        assertEquals("first.example", owid.getDomain(),
                "should read the frame from where the slice starts");
        assertFalse(sliced.hasRemaining(),
                "should have consumed the whole slice");
    }

    /**
     * A direct buffer has no array to walk, so the bytes are taken a copy of.
     * The answer has to be the same one.
     */
    @Test
    void aDirectBufferReadsTheSame() {
        byte[] bytes = concatenated();
        ByteBuffer direct = ByteBuffer.allocateDirect(bytes.length);
        direct.put(bytes);
        ((Buffer) direct).flip();
        assertFalse(direct.hasArray(),
                "the test needs a buffer with no array behind it");

        Owid first = ParseAssert.parsed(Owid.parse(direct));
        assertEquals(FIRST.length, direct.position(),
                "should move a direct buffer on as well");
        Owid second = ParseAssert.parsed(Owid.parse(direct));

        assertEquals("first.example", first.getDomain(),
                "should read the first domain from a direct buffer");
        assertEquals("second.example", second.getDomain(),
                "should read the second domain from a direct buffer");
        assertFalse(direct.hasRemaining(),
                "should have consumed the whole direct buffer");
    }

    /**
     * A read only buffer has no array a caller may reach either, and must
     * read the same way and stay read only.
     */
    @Test
    void aReadOnlyBufferReadsTheSame() {
        ByteBuffer readOnly = ByteBuffer.wrap(FIRST).asReadOnlyBuffer();
        assertTrue(readOnly.isReadOnly(), "the buffer should be read only");

        Owid owid = ParseAssert.parsed(Owid.parse(readOnly));

        assertEquals("first.example", owid.getDomain(),
                "should read from a read only buffer");
        assertFalse(readOnly.hasRemaining(),
                "should have consumed the whole buffer");
    }

    /**
     * The whole buffer read reports the length of the envelope too, which
     * there is the whole of the buffer.
     */
    @Test
    void theWholeBufferReadAlsoReportsTheEnvelopeLength() {
        OwidParseResult result = Owid.parse(FIRST);

        ParseAssert.parsed(result);
        assertEquals(FIRST.length, result.getByteCount(),
                "the envelope should be the whole of the buffer");
        assertEquals(0, Owid.parse(new byte[] {0x04}).getByteCount(),
                "a read that failed should report consuming nothing");
    }
}
