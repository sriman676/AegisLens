package com.aegislens.net;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Trusts exactly one server certificate: the one whose SHA-256 fingerprint the user configured (certificate pinning),
 * as SplitShield's own agents do with its self-signed certificate. Anything else, including a valid public certificate,
 * is refused. Pinning replaces the hostname check (the pin already names one specific server). Never "trust all".
 */
public final class PinnedTrustManager extends X509ExtendedTrustManager {

    private final String pin;

    /** fingerprint: 64 hex digits, colons and case ignored ("AB:CD:..." as shown by browsers and keytool). */
    public PinnedTrustManager(String fingerprint) {
        String clean = fingerprint == null ? "" : fingerprint.replace(":", "").replace(" ", "").toLowerCase(Locale.ROOT);
        if (!clean.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("certificate fingerprint must be a SHA-256 (64 hex digits)");
        }
        this.pin = clean;
    }

    /** The SHA-256 fingerprint of a certificate, lower-case hex. */
    public static String fingerprint(X509Certificate cert) throws CertificateEncodingException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is always available", e);
        }
    }

    private void check(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("server sent no certificate");
        }
        if (!fingerprint(chain[0]).equals(pin)) {
            throw new CertificateException("server certificate does not match the pinned SHA-256 fingerprint");
        }
        chain[0].checkValidity();
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        check(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        check(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        check(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("client certificates are not used");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        throw new CertificateException("client certificates are not used");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        throw new CertificateException("client certificates are not used");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
