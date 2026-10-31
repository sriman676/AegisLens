package com.aegislens.net;

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.util.Optional;
import java.util.function.Function;

/**
 * Proxy settings: a fixed proxy host and port, or "use the system's proxy settings", read from the
 * setting table and applied when the shared HttpClient is built, so changes need a restart (the manual says so).
 * Corporate TLS interception is handled by the JVM truststore, never by switching certificate checks off (N6).
 */
public record NetworkSettings(String proxyHost, int proxyPort, boolean useSystemProxies) {

    public static final String PROXY_HOST = "net.proxy.host";
    public static final String PROXY_PORT = "net.proxy.port";
    public static final String SYSTEM_PROXIES = "net.proxy.system";

    /** Reads the three settings through lookup (key -> value or null). */
    public static NetworkSettings from(Function<String, String> lookup) {
        String host = lookup.apply(PROXY_HOST);
        int port;
        try {
            port = Integer.parseInt(String.valueOf(lookup.apply(PROXY_PORT)).trim());
        } catch (NumberFormatException e) {
            port = 0;
        }
        return new NetworkSettings(host == null ? "" : host.trim(), port, Boolean.parseBoolean(lookup.apply(SYSTEM_PROXIES)));
    }

    /** The proxy selector to use, or empty for the JVM default. */
    public Optional<ProxySelector> selector() {
        if (!proxyHost.isEmpty() && proxyPort > 0 && proxyPort < 65_536) {
            return Optional.of(ProxySelector.of(InetSocketAddress.createUnresolved(proxyHost, proxyPort)));
        }
        if (useSystemProxies) {
            System.setProperty("java.net.useSystemProxies", "true");   // must happen before the first lookup
            return Optional.of(ProxySelector.getDefault());
        }
        return Optional.empty();
    }
}
