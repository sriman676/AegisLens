package com.aegislens.web;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A deliberately small HTTP GET that connects to an address that was ALREADY checked, never resolving the name again
 * (SSRF / DNS rebinding). For https the TLS layer still uses the host name for SNI and checks that
 * the certificate belongs to it. HTTP/1.0 with "Connection: close", so the reply is plain bytes until the end.
 * Limits: 5 s to connect and per read, 64 KB of headers, 1 MB of body.
 */
final class PinnedHttp {

    static final int TIMEOUT_MS = 5000;
    static final int MAX_HEADER_BYTES = 64 * 1024;

    /** Status code, headers (lower-case names, first value wins) and body text. */
    record Response(int status, Map<String, String> headers, String body) {
    }

    private PinnedHttp() {
    }

    /** GET uri from exactly this address; maxBody limits the body (the rest is not read). */
    static Response get(URI uri, InetAddress address, long maxBody) throws IOException {
        boolean https = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() != -1 ? uri.getPort() : https ? 443 : 80;
        Socket plain = new Socket();
        plain.connect(new InetSocketAddress(address, port), TIMEOUT_MS);
        plain.setSoTimeout(TIMEOUT_MS);
        try (Socket socket = https ? tls(plain, uri.getHost(), port) : plain) {
            String path = (uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath())
                    + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
            String request = "GET " + path + " HTTP/1.0\r\nHost: " + uri.getHost() + (uri.getPort() == -1 ? "" : ":" + port)
                    + "\r\nUser-Agent: AegisLens/1.0 (security header check)\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n";
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();
            return read(socket.getInputStream(), maxBody);
        }
    }

    /** TLS over the already connected socket: SNI and certificate check use the host NAME, the connection the checked IP. */
    private static Socket tls(Socket plain, String host, int port) throws IOException {
        SSLSocket s = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(plain, host, port, true);
        SSLParameters p = s.getSSLParameters();
        p.setEndpointIdentificationAlgorithm("HTTPS");                 // the certificate must match the host name
        s.setSSLParameters(p);
        s.startHandshake();
        return s;
    }

    static Response read(InputStream in, long maxBody) throws IOException {
        String head = headerBlock(in);
        String[] lines = head.split("\r\n");
        String[] status = lines[0].split(" ", 3);
        if (status.length < 2 || !status[0].startsWith("HTTP/")) {
            throw new IOException("not an HTTP reply");
        }
        int code;
        try {
            code = Integer.parseInt(status[1]);
        } catch (NumberFormatException e) {
            throw new IOException("bad HTTP status line");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.putIfAbsent(lines[i].substring(0, colon).strip().toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).strip());
            }
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int n;
        while (body.size() < maxBody && (n = in.read(buffer, 0, (int) Math.min(buffer.length, maxBody - body.size()))) != -1) {
            body.write(buffer, 0, n);
        }
        return new Response(code, headers, body.toString(StandardCharsets.UTF_8));
    }

    /** Everything up to the blank line that ends the headers. */
    private static String headerBlock(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int a = 0, b = 0, c = 0, d;
        while ((d = in.read()) != -1) {
            head.write(d);
            if (a == '\r' && b == '\n' && c == '\r' && d == '\n') {
                return head.toString(StandardCharsets.ISO_8859_1).strip();
            }
            if (head.size() > MAX_HEADER_BYTES) {
                throw new IOException("reply headers larger than 64 KB");
            }
            a = b;
            b = c;
            c = d;
        }
        throw new IOException("the connection ended before the reply headers");
    }
}
