package com.aegislens.net;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A local HTTP or HTTPS server for tests (never the real internet). HTTPS uses the test-only self-signed certificate
 * in src/test/resources/net/fake-server.p12, whose SHA-256 fingerprint tests use as the pin.
 */
public final class FakeServer implements AutoCloseable {

    /** Answers one request. */
    @FunctionalInterface
    public interface Handler {
        void handle(HttpExchange ex) throws IOException;
    }

    private final HttpServer server;
    private final boolean https;
    public final AtomicInteger requests = new AtomicInteger();

    private FakeServer(HttpServer server, boolean https) {
        this.server = server;
        this.https = https;
    }

    public static FakeServer http(Map<String, Handler> routes) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        FakeServer f = new FakeServer(s, false);
        f.route(routes);
        s.start();
        return f;
    }

    public static FakeServer https(Map<String, Handler> routes) throws Exception {
        HttpsServer s = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        s.setHttpsConfigurator(new HttpsConfigurator(serverTls()));
        FakeServer f = new FakeServer(s, true);
        f.route(routes);
        s.start();
        return f;
    }

    private void route(Map<String, Handler> routes) {
        routes.forEach((path, h) -> server.createContext(path, ex -> {
            requests.incrementAndGet();
            try {
                h.handle(ex);
            } finally {
                ex.close();
            }
        }));
    }

    public String base() {
        return (https ? "https" : "http") + "://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Sends a JSON body with a status. */
    public static void reply(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("content-type", "application/json");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            ex.getResponseBody().write(bytes);
        }
    }

    public static String body(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    /** The SHA-256 fingerprint of the test certificate (what a user would configure as the pin). */
    public static String certificatePin() throws Exception {
        return PinnedTrustManager.fingerprint((X509Certificate) keyStore().getCertificate("fake"));
    }

    private static KeyStore keyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = FakeServer.class.getResourceAsStream("/net/fake-server.p12")) {
            ks.load(in, "changeit".toCharArray());
        }
        return ks;
    }

    /** The server side of the test certificate (also used by TLS socket tests). */
    public static SSLContext serverTls() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore(), "changeit".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
