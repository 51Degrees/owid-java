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

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Holds the public and private keys used to sign and verify OWIDs. Nothing in
 * this class relates to the web or HTTP.
 *
 * <p>OWID uses ECDSA with the NIST P-256 curve (also known as secp256r1 or
 * prime256v1) and the SHA-256 hash, as required by the specification. The
 * signature is the 64 byte concatenation of the big endian r and s values
 * (IEEE P1363 format). The JDK signature algorithm
 * {@code SHA256withECDSAinP1363Format} produces and consumes this raw 64 byte
 * form directly, so no manual conversion to or from ASN.1 DER is needed.</p>
 *
 * <p>An instance can hold both keys, or only one of them when created with
 * {@link #newSignOnly(String)} or {@link #newVerifyOnly(String)}.</p>
 *
 * <p>Private key import accepts the PKCS#8 ("PRIVATE KEY") PEM form. The SEC1
 * ("EC PRIVATE KEY") PEM form is not supported because the JDK cannot parse it
 * without an additional ASN.1 provider. Keys exported by this implementation,
 * and the fixtures used by the test suite, use PKCS#8 and SPKI so this
 * limitation does not affect interoperability.</p>
 */
public final class Crypto {

    /** The elliptic curve algorithm name used by the JDK key factory. */
    private static final String KEY_ALGORITHM = "EC";

    /** The named curve. secp256r1 is the JDK name for NIST P-256. */
    private static final String CURVE = "secp256r1";

    /**
     * The signature algorithm that produces and consumes the raw 64 byte
     * r concatenated with s form rather than ASN.1 DER.
     */
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSAinP1363Format";

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private Crypto(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Creates a new instance and generates a public and private key pair used
     * to sign and verify OWIDs.
     *
     * @return a new instance holding a fresh P-256 key pair
     * @throws OwidException if the platform cannot generate a P-256 key pair
     */
    public static Crypto generate() throws OwidException {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            generator.initialize(new ECGenParameterSpec(CURVE));
            KeyPair pair = generator.generateKeyPair();
            return new Crypto(pair.getPrivate(), pair.getPublic());
        } catch (GeneralSecurityException e) {
            throw new OwidException("key operation failed because "
                    + e.getMessage(), e);
        }
    }

    /**
     * Creates a new instance for signing OWIDs from the private key PEM
     * provided in PKCS#8 ("PRIVATE KEY") form. The public key is derived from
     * the private key so the instance can also verify.
     *
     * @param privatePem the private key in PKCS#8 PEM form
     * @return a new instance that can sign and verify
     * @throws OwidException if the PEM is empty or not a valid P-256 private
     *                       key
     */
    public static Crypto newSignOnly(String privatePem) throws OwidException {
        if (privatePem == null || privatePem.trim().isEmpty()) {
            throw new OwidException("private key PEM is empty");
        }
        byte[] der = decodePem(privatePem, "PRIVATE KEY");
        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privateKey = factory.generatePrivate(
                    new PKCS8EncodedKeySpec(der));
            PublicKey publicKey = derivePublicKey(privateKey, factory);
            return new Crypto(privateKey, publicKey);
        } catch (GeneralSecurityException e) {
            throw new OwidException("key operation failed because "
                    + e.getMessage(), e);
        }
    }

    /**
     * Creates a new instance for verifying OWIDs from the public key PEM
     * provided in Subject Public Key Info (SPKI, "PUBLIC KEY") form.
     *
     * @param publicPem the public key in SPKI PEM form
     * @return a new instance that can verify but not sign
     * @throws OwidException if the PEM is empty or not a valid P-256 public
     *                       key
     */
    public static Crypto newVerifyOnly(String publicPem) throws OwidException {
        if (publicPem == null || publicPem.trim().isEmpty()) {
            throw new OwidException("public key PEM is empty");
        }
        byte[] der = decodePem(publicPem, "PUBLIC KEY");
        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = factory.generatePublic(
                    new X509EncodedKeySpec(der));
            return new Crypto(null, publicKey);
        } catch (GeneralSecurityException e) {
            throw new OwidException("key operation failed because "
                    + e.getMessage(), e);
        }
    }

    /**
     * Signs the byte array with the private key and returns the 64 byte
     * signature.
     *
     * @param data the bytes to sign
     * @return the 64 byte signature
     * @throws OwidException if the instance was created for verification only,
     *                       or the signing operation fails
     */
    public byte[] signByteArray(byte[] data) throws OwidException {
        if (privateKey == null) {
            throw new OwidException(
                    "instance of Crypto cannot be used to generate a signature");
        }
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data);
            byte[] bytes = signature.sign();
            if (bytes.length != Owid.SIGNATURE_LENGTH) {
                throw Io.invalidSignatureLength(bytes.length);
            }
            return bytes;
        } catch (GeneralSecurityException e) {
            throw new OwidException("key operation failed because "
                    + e.getMessage(), e);
        }
    }

    /**
     * Returns true if the signature is valid for the data.
     *
     * <p>A signature of the wrong length is rejected with an
     * {@link OwidException}. A signature of the right length that does not
     * match the data returns false rather than throwing.</p>
     *
     * @param data      the bytes that were signed
     * @param signature the 64 byte signature to check
     * @return true if the signature verifies, false otherwise
     * @throws OwidException if the instance has no public key, or the
     *                       signature length is not 64 bytes
     */
    public boolean verifyByteArray(byte[] data, byte[] signature)
            throws OwidException {
        if (publicKey == null) {
            throw new OwidException(
                    "instance of Crypto cannot be used to verify a signature");
        }
        if (signature.length != Owid.SIGNATURE_LENGTH) {
            throw Io.invalidSignatureLength(signature.length);
        }
        try {
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            // Bytes that can not form a valid signature can never verify.
            return false;
        }
    }

    /**
     * Returns the public key in Subject Public Key Info (SPKI) PEM form for
     * use with the well known end points or other implementations.
     *
     * @return the public key as SPKI PEM text
     * @throws OwidException if the instance has no public key
     */
    public String subjectPublicKeyInfo() throws OwidException {
        if (publicKey == null) {
            throw new OwidException(
                    "instance of Crypto cannot be used to export a public key");
        }
        return encodePem("PUBLIC KEY", publicKey.getEncoded());
    }

    /**
     * Returns the public key in PEM form. Alias of
     * {@link #subjectPublicKeyInfo()}.
     *
     * @return the public key as SPKI PEM text
     * @throws OwidException if the instance has no public key
     */
    public String publicKeyPem() throws OwidException {
        return subjectPublicKeyInfo();
    }

    /**
     * Returns the private key in PKCS#8 PEM form.
     *
     * @return the private key as PKCS#8 PEM text
     * @throws OwidException if the instance has no private key
     */
    public String privateKeyPem() throws OwidException {
        if (privateKey == null) {
            throw new OwidException(
                    "instance of Crypto cannot be used to export a private key");
        }
        return encodePem("PRIVATE KEY", privateKey.getEncoded());
    }

    /**
     * Returns true if the instance can be used to sign OWIDs.
     *
     * @return true if a private key is present
     */
    public boolean canSign() {
        return privateKey != null;
    }

    /**
     * Returns true if the instance can be used to verify OWIDs.
     *
     * @return true if a public key is present
     */
    public boolean canVerify() {
        return publicKey != null;
    }

    private static PublicKey derivePublicKey(PrivateKey privateKey,
            KeyFactory factory) throws GeneralSecurityException {
        java.security.interfaces.ECPrivateKey ecPrivate =
                (java.security.interfaces.ECPrivateKey) privateKey;
        java.security.spec.ECParameterSpec params = ecPrivate.getParams();
        java.security.spec.ECPoint w = params.getGenerator();
        java.security.spec.ECPoint point = multiply(ecPrivate.getS(), w, params);
        return factory.generatePublic(
                new java.security.spec.ECPublicKeySpec(point, params));
    }

    private static java.security.spec.ECPoint multiply(
            java.math.BigInteger k, java.security.spec.ECPoint g,
            java.security.spec.ECParameterSpec params) {
        java.math.BigInteger p = ((java.security.spec.ECFieldFp)
                params.getCurve().getField()).getP();
        java.math.BigInteger a = params.getCurve().getA();
        java.security.spec.ECPoint result =
                java.security.spec.ECPoint.POINT_INFINITY;
        java.security.spec.ECPoint addend = g;
        java.math.BigInteger n = k;
        while (n.signum() > 0) {
            if (n.testBit(0)) {
                result = add(result, addend, a, p);
            }
            addend = add(addend, addend, a, p);
            n = n.shiftRight(1);
        }
        return result;
    }

    private static java.security.spec.ECPoint add(
            java.security.spec.ECPoint q, java.security.spec.ECPoint r,
            java.math.BigInteger a, java.math.BigInteger p) {
        if (q.equals(java.security.spec.ECPoint.POINT_INFINITY)) {
            return r;
        }
        if (r.equals(java.security.spec.ECPoint.POINT_INFINITY)) {
            return q;
        }
        java.math.BigInteger qx = q.getAffineX();
        java.math.BigInteger qy = q.getAffineY();
        java.math.BigInteger rx = r.getAffineX();
        java.math.BigInteger ry = r.getAffineY();
        java.math.BigInteger slope;
        if (qx.equals(rx)) {
            if (qy.add(ry).mod(p).signum() == 0) {
                return java.security.spec.ECPoint.POINT_INFINITY;
            }
            java.math.BigInteger numerator = qx.multiply(qx)
                    .multiply(java.math.BigInteger.valueOf(3)).add(a).mod(p);
            java.math.BigInteger denominator = qy.shiftLeft(1).mod(p);
            slope = numerator.multiply(denominator.modInverse(p)).mod(p);
        } else {
            java.math.BigInteger numerator = ry.subtract(qy).mod(p);
            java.math.BigInteger denominator = rx.subtract(qx).mod(p);
            slope = numerator.multiply(denominator.modInverse(p)).mod(p);
        }
        java.math.BigInteger x = slope.multiply(slope).subtract(qx).subtract(rx)
                .mod(p);
        java.math.BigInteger y = slope.multiply(qx.subtract(x)).subtract(qy)
                .mod(p);
        return new java.security.spec.ECPoint(x, y);
    }

    /**
     * Decodes a PEM block, accepting and ignoring the begin and end lines for
     * the label provided. The base 64 body is decoded leniently so that both
     * padded and unpadded forms are accepted.
     */
    private static byte[] decodePem(String pem, String label)
            throws OwidException {
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int start = pem.indexOf(begin);
        int finish = pem.indexOf(end);
        if (start < 0 || finish < 0 || finish < start) {
            throw new OwidException("key operation failed because the PEM is not "
                    + "a '" + label + "' block");
        }
        String body = pem.substring(start + begin.length(), finish);
        StringBuilder cleaned = new StringBuilder();
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (!Character.isWhitespace(c)) {
                cleaned.append(c);
            }
        }
        try {
            return Base64.getMimeDecoder().decode(cleaned.toString());
        } catch (IllegalArgumentException e) {
            throw new OwidException("key operation failed because the PEM body "
                    + "is not valid base 64", e);
        }
    }

    /** Encodes DER key bytes as a PEM block with the label provided. */
    private static String encodePem(String label, byte[] der) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder builder = new StringBuilder();
        builder.append("-----BEGIN ").append(label).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            builder.append(base64, i, Math.min(i + 64, base64.length()));
            builder.append('\n');
        }
        builder.append("-----END ").append(label).append("-----\n");
        return builder.toString();
    }
}
