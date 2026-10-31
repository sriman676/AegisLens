package com.aegislens.net;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * One shared HttpClient for the whole app (LLM providers, webhook, feeds), built once with the proxy settings, plus
 * certificate-pinned clients for servers with a self-signed certificate (SplitShield). Redirects are never followed
 * automatically. close() releases every client at shutdown.
 */
public final class HttpClientFactory implements AutoCloseable {

    public static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

    private final NetworkSettings settings;
    private final HttpClient shared;
    private final List<HttpClient> pinned = new ArrayList<>();

    public HttpClientFactory(NetworkSettings settings) {
        this.settings = settings;
        this.shared = builder().build();
    }

    /** No proxy settings: the JVM defaults. */
    public static HttpClientFactory defaults() {
        return new HttpClientFactory(new NetworkSettings("", 0, false));
    }

    public HttpClient client() {
        return shared;
    }

    /** A client that only talks to the server whose certificate has this SHA-256 fingerprint. */
    public synchronized HttpClient pinnedClient(String sha256Fingerprint) {
        try {
            SSLContext tls = SSLContext.getInstance("TLS");
            tls.init(null, new TrustManager[] {new PinnedTrustManager(sha256Fingerprint)}, null);
            HttpClient client = builder().sslContext(tls).build();
            pinned.add(client);
            return client;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("TLS is not available", e);
        }
    }

    private HttpClient.Builder builder() {
        HttpClient.Builder b = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER);
        settings.selector().ifPresent(b::proxy);
        return b;
    }

    @Override
    public synchronized void close() {
        shared.close();
        for (HttpClient c : pinned) {
            c.close();
        }
        pinned.clear();
    }
}
