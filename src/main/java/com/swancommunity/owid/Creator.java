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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;

/**
 * Needed to create new OWIDs.
 *
 * <p>A creator binds the domain that hosts the well known end points to the
 * crypto instance holding the signing key. Creating an OWID sets its domain
 * to the creator domain, its date to the current time and its version to the
 * current version, signs it, and hands back the finished thing.</p>
 *
 * <p>There is no way to sign an OWID that already exists, because there is no
 * way to obtain an unsigned one, so nothing outside the library is available
 * to be signed. Signing a parsed OWID again would replace the signature its
 * fields were read with, which is why the library does not offer it.</p>
 */
public final class Creator {

    private final String domain;
    private final Crypto crypto;

    private Creator(String domain, Crypto crypto) {
        this.domain = domain;
        this.crypto = crypto;
    }

    /**
     * Creates a new creator for the domain using the crypto instance for
     * signing.
     *
     * <p>The domain is refused here if it is longer than the maximum
     * published for a domain name, being the same bound parsing applies, so
     * a creator can never be built that would produce an OWID this library
     * would refuse to read. The refusal arrives when the caller supplies the
     * domain rather than later when an OWID is signed.</p>
     *
     * @param domain the domain associated with the creator
     * @param crypto the crypto instance that can sign
     * @return the creator
     * @throws OwidException if the domain is empty or whitespace, is longer
     *                       than the maximum published for a domain name, or
     *                       the crypto instance cannot sign
     */
    public static Creator create(String domain, Crypto crypto)
            throws OwidException {
        if (domain == null || domain.trim().isEmpty()) {
            throw new OwidException("domain '" + domain + "' is not valid");
        }
        if (domain.getBytes(StandardCharsets.UTF_8).length
                > Io.MAXIMUM_DOMAIN_LENGTH) {
            throw Io.domainTooLong();
        }
        if (!crypto.canSign()) {
            throw new OwidException(
                    "instance of Crypto cannot be used to generate a signature");
        }
        return new Creator(domain, crypto);
    }

    /**
     * Creates a new creator for the domain from the private key PEM provided.
     *
     * @param domain     the domain associated with the creator
     * @param privatePem the private key in PKCS#8 PEM form
     * @return the creator
     * @throws OwidException if the domain is empty or longer than the
     *                       maximum published for a domain name, or the PEM
     *                       is not a valid private key
     */
    public static Creator fromPrivatePem(String domain, String privatePem)
            throws OwidException {
        return create(domain, Crypto.newSignOnly(privatePem));
    }

    /**
     * Returns the domain associated with the OWID creator. The domain hosts
     * the well known end points that provide public keys and other
     * information required by the OWID specification.
     *
     * @return the domain
     */
    public String domain() {
        return domain;
    }

    /**
     * Returns the crypto instance used to sign OWIDs from this creator.
     *
     * @return the crypto instance
     */
    public Crypto crypto() {
        return crypto;
    }

    /**
     * Creates a new signed OWID for this creator carrying the string as the
     * UTF-8 payload.
     *
     * @param value the payload string
     * @return the signed OWID
     * @throws OwidException if the payload is null, a field cannot be
     *                       encoded, or the signing operation fails
     */
    public Owid createString(String value) throws OwidException {
        return createString(value, Collections.<Owid>emptyList());
    }

    /**
     * Creates a new signed OWID for this creator carrying the bytes as the
     * payload.
     *
     * @param value the payload bytes
     * @return the signed OWID
     * @throws OwidException if the payload is null, a field cannot be
     *                       encoded, or the signing operation fails
     */
    public Owid createBytes(byte[] value) throws OwidException {
        return createBytes(value, Collections.<Owid>emptyList());
    }

    /**
     * Creates a new signed OWID carrying the string as the UTF-8 payload,
     * with the other OWIDs covered by the same signature so that a tree can
     * be verified as a whole. The same others, in the same order, must be
     * passed when verifying.
     *
     * @param value  the payload string
     * @param others the other OWIDs to cover with the signature
     * @return the signed OWID
     * @throws OwidException see {@link #createString(String)}
     */
    public Owid createString(String value, List<Owid> others)
            throws OwidException {
        if (value == null) {
            throw new OwidException("payload is null");
        }
        return createBytes(value.getBytes(StandardCharsets.UTF_8), others);
    }

    /**
     * Creates a new signed OWID carrying the bytes as the payload, with the
     * other OWIDs covered by the same signature.
     *
     * <p>This is one of only two ways an OWID reaches calling code, the other
     * being a successful read of a complete serialized one. The creator owns
     * the version, the domain, the date and the signature, and a caller
     * supplies the payload and nothing else, so there is no moment at which a
     * partly built OWID exists for anyone to hold or pass on.</p>
     *
     * @param value  the payload bytes
     * @param others the other OWIDs to cover with the signature
     * @return the signed OWID
     * @throws OwidException see {@link #createBytes(byte[])}
     */
    public Owid createBytes(byte[] value, List<Owid> others)
            throws OwidException {
        if (value == null) {
            throw new OwidException("payload is null");
        }
        if (others == null) {
            throw new OwidException("others is null");
        }
        Version version = Version.current();
        Instant date = Instant.now().truncatedTo(ChronoUnit.MINUTES);
        byte[] payload = value.clone();
        byte[] data = Owid.dataForCrypto(
                version, domain, date, payload, others);
        byte[] signature = crypto.signByteArray(data);
        if (signature.length != Owid.SIGNATURE_LENGTH) {
            throw Io.invalidSignatureLength(signature.length);
        }
        return new Owid(version, domain, date, payload, signature);
    }
}
