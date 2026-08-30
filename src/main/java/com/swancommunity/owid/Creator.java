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
 * crypto instance holding the signing key. Signing an OWID sets its domain to
 * the creator domain, its date to the current time, and its version to the
 * current version, then produces the signature.</p>
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
     * Signs the OWID provided, setting the domain to the creator domain, the
     * date to the current time, and the version to the current version.
     *
     * @param owid the OWID to sign
     * @throws OwidException if a field cannot be encoded or the signing
     *                       operation fails
     */
    public void sign(Owid owid) throws OwidException {
        signWithOthers(owid, Collections.emptyList());
    }

    /**
     * Signs the OWID provided together with the other OWIDs provided. The same
     * others, in the same order, must be passed when verifying.
     *
     * @param owid   the OWID to sign
     * @param others the other OWIDs to cover with the signature
     * @throws OwidException if a field cannot be encoded or the signing
     *                       operation fails
     */
    public void signWithOthers(Owid owid, List<Owid> others)
            throws OwidException {
        owid.setVersion(Version.current());
        owid.setDomain(domain);
        owid.setDate(Instant.now().truncatedTo(ChronoUnit.MINUTES));
        byte[] data = owid.dataForCrypto(others);
        byte[] signature = crypto.signByteArray(data);
        if (signature.length != Owid.SIGNATURE_LENGTH) {
            throw Io.invalidSignatureLength(signature.length);
        }
        owid.setSignature(signature);
    }

    /**
     * Creates a new signed OWID for the creator containing the string as the
     * UTF-8 payload.
     *
     * @param value the payload string
     * @return the signed OWID
     * @throws OwidException see {@link #sign(Owid)}
     */
    public Owid signString(String value) throws OwidException {
        return signBytes(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Creates a new signed OWID for the creator containing the bytes as the
     * payload.
     *
     * @param value the payload bytes
     * @return the signed OWID
     * @throws OwidException see {@link #sign(Owid)}
     */
    public Owid signBytes(byte[] value) throws OwidException {
        Owid owid = new Owid();
        owid.setPayload(value);
        sign(owid);
        return owid;
    }
}
