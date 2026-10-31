package com.aegislens.intrusion;

import java.time.Instant;

/**
 * One parsed log line: when, from which source, which IP and user, what happened, and for web requests the method,
 * path, status and user agent. raw keeps the original line (capped) for evidence. Fields that do not apply are null
 * (status is 0).
 */
public record LogEvent(Instant timestamp, String source, String ip, String user, Action action,
                       String method, String path, int status, String userAgent, String detail, String raw) {

    /** What the line says happened. */
    public enum Action {
        FAILED_LOGIN, SUCCESS_LOGIN, INVALID_USER, DISCONNECT, MAX_AUTH, ACCOUNT_LOCKOUT, WEB_REQUEST
    }

    /** A login-related event (SSH, Windows). */
    public static LogEvent login(Instant timestamp, String source, String ip, String user, Action action,
                                 String detail, String raw) {
        return new LogEvent(timestamp, source, ip, user, action, null, null, 0, null, detail, raw);
    }

    /** A web request from an access log. */
    public static LogEvent web(Instant timestamp, String source, String ip, String user, String method, String path,
                               int status, String userAgent, String raw) {
        return new LogEvent(timestamp, source, ip, user, Action.WEB_REQUEST, method, path, status, userAgent, null, raw);
    }

    public boolean isClientError() {
        return status >= 400 && status < 500;
    }
}
