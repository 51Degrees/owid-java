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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fetches the signing public key of a creator from the well known end point
 * on the domain the OWID carries, asking for the key that was in force on the
 * date the OWID carries.
 *
 * <p>The end point is
 * {@code /owid/api/v{n}/public-key?date={minutes}&amp;format=pkcs}, where the
 * version in the path is the version byte of the OWID being checked rather
 * than a constant, and the minutes are counted from 2020-01-01 in the same
 * way the OWID stores the date. Creators rotate weekly, so without the date
 * only identifiers signed since the most recent rotation can be verified and
 * every older one reads as not matching. A creator that ignores the
 * parameter returns its current key, so every identifier it signed under an
 * earlier key reads as not matching, which is why a creator that rotates its
 * key has to honour the date.</p>
 *
 * <p>Only the JDK is used, so the library keeps its promise of no runtime
 * dependencies and still runs on Java 8, which has no HTTP client of its
 * own.</p>
 *
 * <p>The Rust port answers the same question with {@code Owid::verify_status}
 * and the Go port with {@code SignatureStatusFromDomain}.</p>
 */
public final class PublicKeyFetch {

    /** How long to wait for the connection to be made, in milliseconds. */
    private static final int CONNECT_TIMEOUT_MILLISECONDS = 5000;

    /** How long to wait for the response, in milliseconds. */
    private static final int READ_TIMEOUT_MILLISECONDS = 10000;

    /**
     * The most keys held in the cache before the cache is emptied and filled
     * again. A bound is needed because a verifier sees identifiers from many
     * domains and many weeks, and an unbounded map would grow for as long as
     * the process runs.
     */
    private static final int MAXIMUM_CACHED_KEYS = 1024;

    /**
     * Keys already fetched, held against the URL the keys were fetched from.
     *
     * <p>The specification asks implementations to cache so that verifying
     * many identifiers does not mean repeating requests to another
     * processor. Holding the key against the whole URL is safe because the
     * URL names the domain, the version and the minute, and the key a
     * creator published for a minute in the past does not change.</p>
     */
    private static final Map<String, String> CACHE =
            new ConcurrentHashMap<String, String>();

    private PublicKeyFetch() {
    }

    /**
     * Returns the URL of the public key end point for the OWID, using the
     * scheme provided, which is normally {@code https}.
     *
     * <p>The date the OWID carries is sent as the {@code date} parameter,
     * counted in whole minutes from 2020-01-01, so that a creator which
     * rotates its key returns the key that was in force when this OWID was
     * signed. The parameter is left out where the date cannot be counted,
     * which no OWID this library reads can be, because the wire format
     * cannot hold such a date.</p>
     *
     * @param owid   the OWID whose creator key is wanted
     * @param scheme the scheme to use, normally {@code https}
     * @return the URL of the public key end point
     * @throws OwidException if the OWID or the scheme is missing, or the
     *                       domain the OWID carries is not a domain this
     *                       library will put in a URL
     */
    public static String publicKeyUrl(Owid owid, String scheme)
            throws OwidException {
        if (owid == null) {
            throw new OwidException("the OWID is missing");
        }
        if (scheme == null || scheme.trim().isEmpty()) {
            throw new OwidException("the scheme is missing");
        }
        String domain = owid.getDomain();
        checkDomain(domain);
        StringBuilder url = new StringBuilder();
        url.append(scheme).append("://").append(domain)
                .append(Endpoints.publicKeyPath(owid.getVersion()));
        long minutes = Io.minutesSinceBase(owid.getDate());
        url.append('?');
        if (minutes >= 0) {
            url.append("date=").append(minutes).append('&');
        }
        url.append("format=pkcs");
        return url.toString();
    }

    /**
     * Returns the public key PEM of the creator of the OWID, for the date
     * the OWID carries.
     *
     * @param owid   the OWID whose creator key is wanted
     * @param scheme the scheme to use, normally {@code https}
     * @return the public key in PEM form
     * @throws PublicKeyFetchException if the key could not be obtained, with
     *                                 the status to report for the
     *                                 identifier
     * @throws OwidException           if the OWID, the scheme or the domain
     *                                 is not usable
     */
    public static String publicKeyPem(Owid owid, String scheme)
            throws OwidException {
        return publicKeyPemAtUrl(publicKeyUrl(owid, scheme),
                owid.getDomain());
    }

    /**
     * Asks whether the signature on the OWID is genuine, fetching the key
     * that was in force when the OWID was signed from the creator domain.
     *
     * <p>A key that cannot be fetched is
     * {@link OwidSignatureStatus#KEY_UNAVAILABLE} and one that arrives in a
     * form this library cannot read is
     * {@link OwidSignatureStatus#INVALID_KEY}. Neither is
     * {@link OwidSignatureStatus#SIGNATURE_INVALID}, because an outage or a
     * badly served key leaves the signature unjudged, and reporting either
     * as invalid would read as an attack.</p>
     *
     * @param owid   the OWID to check
     * @param scheme the scheme to use, normally {@code https}
     * @param others the other OWIDs that were signed together with this one,
     *               in the same order as when signed
     * @return the outcome of the check
     */
    public static OwidVerificationResult verify(Owid owid, String scheme,
            List<Owid> others) {
        String url;
        try {
            url = publicKeyUrl(owid, scheme);
        } catch (OwidException e) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.KEY_UNAVAILABLE);
        }
        return verifyAtUrl(owid, url, others);
    }

    /**
     * Empties the cache of keys already fetched. Provided so that a long
     * running process can release the memory, and so that a test can start
     * from a known state.
     */
    public static void clearCache() {
        CACHE.clear();
    }

    /**
     * The work {@link #verify(Owid, String, List)} does once the URL is
     * known, kept apart so that the tests drive the real fetch against a key
     * end point the tests can stand up locally rather than against a near
     * copy of the fetch.
     */
    static OwidVerificationResult verifyAtUrl(Owid owid, String url,
            List<Owid> others) {
        String pem;
        try {
            pem = publicKeyPemAtUrl(url, owid.getDomain());
        } catch (PublicKeyFetchException e) {
            return OwidVerificationResult.of(e.getStatus());
        } catch (OwidException e) {
            return OwidVerificationResult.of(
                    OwidSignatureStatus.KEY_UNAVAILABLE);
        }
        return owid.verify(pem, others);
    }

    /**
     * Fetches the PEM at the URL, answering from the cache where the same
     * URL has already been fetched.
     */
    static String publicKeyPemAtUrl(String url, String domain)
            throws OwidException {
        String cached = CACHE.get(url);
        if (cached != null) {
            return cached;
        }
        String pem = read(url, domain);
        if (CACHE.size() >= MAXIMUM_CACHED_KEYS) {
            CACHE.clear();
        }
        CACHE.put(url, pem);
        return pem;
    }

    /** Performs the request and returns the body as text. */
    private static String read(String url, String domain)
            throws OwidException {
        HttpURLConnection connection = null;
        try {
            URLConnection opened = new URL(url).openConnection();
            if ((opened instanceof HttpURLConnection) == false) {
                // A scheme the caller chose that does not make an HTTP
                // request, such as file. Reported as a key that could not be
                // obtained rather than allowed to escape as a cast failure,
                // because every route into this class promises a status.
                throw new PublicKeyFetchException(
                        "the scheme used for domain " + quoted(domain)
                                + " does not make an HTTP request",
                        OwidSignatureStatus.KEY_UNAVAILABLE,
                        domain,
                        0,
                        null);
            }
            connection = (HttpURLConnection) opened;
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MILLISECONDS);
            connection.setReadTimeout(READ_TIMEOUT_MILLISECONDS);
            connection.setRequestProperty("Accept", "text/plain");
            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                drain(connection.getErrorStream());
                throw new PublicKeyFetchException(
                        "domain " + quoted(domain) + " returned code '" + code
                                + "' for the public key",
                        OwidSignatureStatus.KEY_UNAVAILABLE,
                        domain,
                        code,
                        null);
            }
            InputStream body = connection.getInputStream();
            try {
                return new String(readAll(body), StandardCharsets.UTF_8);
            } finally {
                body.close();
            }
        } catch (IOException e) {
            // A refused connection, a name that does not resolve and a
            // timeout all arrive here, and all of them mean the signature
            // was never examined.
            throw new PublicKeyFetchException(
                    "the public key could not be fetched from domain "
                            + quoted(domain),
                    OwidSignatureStatus.KEY_UNAVAILABLE,
                    domain,
                    0,
                    e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /** The value in single quotes, for a message. */
    private static String quoted(String value) {
        return "'" + value + "'";
    }

    /** Reads a stream to its end. */
    private static byte[] readAll(InputStream stream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] block = new byte[4096];
        int read = stream.read(block);
        while (read > 0) {
            buffer.write(block, 0, read);
            read = stream.read(block);
        }
        return buffer.toByteArray();
    }

    /** Closes the error body of a refused request, where there is one. */
    private static void drain(InputStream stream) {
        if (stream == null) {
            return;
        }
        try {
            stream.close();
        } catch (IOException e) {
            // Nothing useful can be done about a body that will not close,
            // and the refusal itself is what the caller is told about.
        }
    }

    /**
     * Refuses a domain that would change the shape of the URL rather than
     * name a host in it.
     *
     * <p>The domain arrives inside an OWID, which came from outside, so the
     * text is not the library's own. Letters, digits, dots and hyphens are
     * all a domain name needs, and anything else could add a query, a
     * fragment, a port, credentials or a path and send the request somewhere
     * other than the creator.</p>
     */
    private static void checkDomain(String domain) throws OwidException {
        if (domain == null || domain.isEmpty()) {
            throw new OwidException("the OWID carries no domain");
        }
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '.' || c == '-';
            if (allowed == false) {
                // The domain is not repeated back, because the text arrived
                // from outside and a refusal is often logged.
                throw new OwidException(
                        "the domain in the OWID is not a domain name this "
                                + "library will request a key from");
            }
        }
    }
}
