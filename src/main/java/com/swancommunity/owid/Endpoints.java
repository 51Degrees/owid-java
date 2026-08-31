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
 * Helpers for hosting the well known end points required by the OWID
 * specification. These are framework agnostic. They return the path and body
 * so that any HTTP server can serve them.
 *
 * <p>The mandatory end points are:</p>
 *
 * <ul>
 *   <li>{@code /owid/api/v{version}/creator} returning JSON with the domain,
 *       common name, and public key of the creator.</li>
 *   <li>{@code /owid/api/v{version}/public-key} returning the public key as
 *       PEM text. The {@code format} query parameter must be {@code spki} or
 *       {@code pkcs}.</li>
 * </ul>
 */
public final class Endpoints {

    private Endpoints() {
    }

    /**
     * Returns the path of the creator end point for the version provided. For
     * example {@code /owid/api/v3/creator}.
     *
     * @param version the OWID version
     * @return the creator path
     */
    public static String creatorPath(Version version) {
        return "/owid/api/v" + (version.asByte() & 0xFF) + "/creator";
    }

    /**
     * Returns the path of the public key end point for the version provided.
     * For example {@code /owid/api/v3/public-key}.
     *
     * @param version the OWID version
     * @return the public key path
     */
    public static String publicKeyPath(Version version) {
        return "/owid/api/v" + (version.asByte() & 0xFF) + "/public-key";
    }

    /**
     * Returns the JSON body for the creator end point. The JSON has the
     * fields domain, name, publicKeySPKI, and contractURL named exactly as
     * required by the specification.
     *
     * @param creator     the creator
     * @param name        the common name of the creator
     * @param contractUrl the URL with the terms associated with the data
     * @return the JSON body
     * @throws OwidException if the public key cannot be exported
     */
    public static String creatorResponse(Creator creator, String name,
            String contractUrl) throws OwidException {
        String spki = creator.crypto().subjectPublicKeyInfo();
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendField(json, "domain", creator.domain());
        json.append(',');
        appendField(json, "name", name);
        json.append(',');
        appendField(json, "publicKeySPKI", spki);
        json.append(',');
        appendField(json, "contractURL", contractUrl);
        json.append('}');
        return json.toString();
    }

    /**
     * Returns the text body for the public key end point. The specification
     * allows the key to be requested in SPKI or PKCS form. This
     * implementation returns the SPKI PEM for both values because the
     * importers accept it.
     *
     * @param creator the creator
     * @param format  the format parameter, {@code spki} or {@code pkcs}
     * @return the public key PEM
     * @throws OwidException if the format is not valid, or the public key
     *                       cannot be exported
     */
    public static String publicKeyResponse(Creator creator, String format)
            throws OwidException {
        if ("spki".equals(format) || "pkcs".equals(format)) {
            return creator.crypto().subjectPublicKeyInfo();
        }
        // The value is not repeated back, because it arrives on a query
        // string from whoever called the end point and a refusal is often
        // logged.
        throw new OwidException(
                "format parameter 'spki' or 'pkcs' must be provided");
    }

    private static void appendField(StringBuilder json, String name,
            String value) {
        json.append('"').append(name).append("\":\"")
                .append(escape(value)).append('"');
    }

    /** Escapes a string for inclusion in a JSON string literal. */
    private static String escape(String value) {
        StringBuilder builder = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        builder.append(String.format("\\u%04x", (int) c));
                    } else {
                        builder.append(c);
                    }
            }
        }
        return builder.toString();
    }
}
