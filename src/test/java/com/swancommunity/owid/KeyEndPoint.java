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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A stand in for the public key end point of a creator, answering the way the
 * cloud controller does and serving the real published 51d.es schedule.
 *
 * <p>The live end point answers 401 without a credential, so the tests stand
 * this up on the loopback address instead, which is what the Rust and Go
 * ports do for the same reason.</p>
 *
 * <p>A request naming a date is served the key that was in force then, a
 * request without one is served the key in force at the moment of the
 * request, a date after that moment is read as that moment, and a date the
 * schedule does not reach is a 404. That is how the cloud answers, and the
 * moment of the request is fixed at {@link #REQUEST_MOMENT} so the tests are
 * repeatable. The date parameter of every request is recorded, so a test can
 * say what went over the wire rather than only what the URL builder
 * returned.</p>
 */
final class KeyEndPoint {

    /**
     * The moment the end point treats as now, ten days after the fixture
     * identifier was signed and in the week that followed. Every port's
     * stand in uses this moment. An undated request is therefore served a
     * key other than the one that signed the fixture, exactly as it would
     * be against the live creator in that week.
     */
    static final Instant REQUEST_MOMENT =
            Instant.parse("2026-09-14T00:00:00Z");

    /** What the end point serves. */
    enum Answer {

        /** The published schedule, chosen by the date requested. */
        SCHEDULE,

        /** Text shaped like a PEM that no key can be read out of. */
        BROKEN_KEY
    }

    private final HttpServer server;
    private final String base;
    private final List<String> dates =
            Collections.synchronizedList(new ArrayList<String>());

    private KeyEndPoint(HttpServer server, String base) {
        this.server = server;
        this.base = base;
    }

    /** Starts an end point serving the published schedule. */
    static KeyEndPoint start() throws IOException, OwidException {
        return start(Answer.SCHEDULE);
    }

    /** Starts an end point serving what the answer says. */
    static KeyEndPoint start(final Answer answer)
            throws IOException, OwidException {
        final PublicKeySchedule schedule = KeyFixtures.schedule();
        HttpServer server = HttpServer.create(new InetSocketAddress(
                InetAddress.getByName("127.0.0.1"), 0), 0);
        final KeyEndPoint endPoint = new KeyEndPoint(server,
                "http://127.0.0.1:" + server.getAddress().getPort());
        server.createContext("/", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String date = parameter(
                        exchange.getRequestURI().getRawQuery(), "date");
                endPoint.dates.add(date);
                String body;
                try {
                    body = body(schedule, answer, date);
                } catch (NumberFormatException malformed) {
                    // A date that is not a number is refused, as the cloud
                    // refuses it, rather than failing inside the handler.
                    exchange.sendResponseHeaders(400, -1);
                    exchange.close();
                    return;
                }
                if (body == null) {
                    exchange.sendResponseHeaders(404, -1);
                    exchange.close();
                    return;
                }
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders()
                        .set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(200, bytes.length);
                OutputStream stream = exchange.getResponseBody();
                try {
                    stream.write(bytes);
                } finally {
                    stream.close();
                }
            }
        });
        server.start();
        return endPoint;
    }

    /** Stops the end point. */
    void stop() {
        server.stop(0);
    }

    /** The address the end point is listening on. */
    String base() {
        return base;
    }

    /**
     * The URL a fetch would use, with the creator domain replaced by this end
     * point. The path and the query are the ones the library builds, so what
     * is under test is the real URL rather than a copy of it.
     */
    String urlFor(Owid owid) throws OwidException {
        String built = PublicKeyFetch.publicKeyUrl(owid, "http");
        int at = built.indexOf(owid.getDomain());
        return base + built.substring(at + owid.getDomain().length());
    }

    /** The date parameter of every request served so far, in order. */
    List<String> dates() {
        synchronized (dates) {
            return new ArrayList<String>(dates);
        }
    }

    /** The body to serve, or null where the end point has no key. */
    private static String body(PublicKeySchedule schedule, Answer answer,
            String date) {
        if (answer == Answer.BROKEN_KEY) {
            // Shaped like a PEM, with a body no key can be read out of. This
            // is the 30 August 2026 fault, where the end points served PEM a
            // strict parser refused and good identifiers went unverified.
            return "-----BEGIN PUBLIC KEY-----\n"
                    + "bm90IGEga2V5\n"
                    + "-----END PUBLIC KEY-----\n";
        }
        Instant asked = REQUEST_MOMENT;
        if (date != null) {
            asked = Io.baseDate()
                    .plus(Duration.ofMinutes(Long.parseLong(date)));
            if (asked.isAfter(REQUEST_MOMENT)) {
                asked = REQUEST_MOMENT;
            }
        }
        DatedPublicKey key = schedule.keyInForce(asked);
        if (key == null) {
            return null;
        }
        return key.getPublicKeyPem();
    }

    /** The value of a parameter in a query, or null where there is none. */
    private static String parameter(String query, String name) {
        if (query == null) {
            return null;
        }
        for (String pair : query.split("&")) {
            if (pair.startsWith(name + "=")) {
                return pair.substring(name.length() + 1);
            }
        }
        return null;
    }
}
