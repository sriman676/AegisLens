package com.aegislens.net;

import java.io.IOException;

/** A server sent more bytes than we accept; the download was stopped. Never retried. */
public class ResponseTooLargeException extends IOException {

    public ResponseTooLargeException(long limit) {
        super("response larger than " + limit + " bytes; stopped reading");
    }
}
