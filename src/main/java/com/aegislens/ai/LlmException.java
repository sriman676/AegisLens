package com.aegislens.ai;

/**
 * Any failure talking to an AI provider, with a Kind so the UI can say exactly what went wrong instead of
 * a generic error. Messages never contain an API key or the server's reply body.
 */
public class LlmException extends Exception {

    /** What went wrong, with the message the user sees. */
    public enum Kind {
        NOT_CONFIGURED("This provider is not set up (no key or address)."),
        AUTH("The key was refused: check the API key or token."),
        RATE_LIMIT("The provider is busy (rate limit). Try again in a minute."),
        SERVER("The provider had a server error. Try again later."),
        NETWORK("Could not reach the provider (network, proxy or certificate)."),
        TIMEOUT("The provider did not answer in time."),
        BAD_RESPONSE("The provider sent an answer we could not read."),
        BLOCKED("The provider refused to answer (safety filter)."),
        MODEL_NOT_FOUND("Unknown model: check the model name in Settings."),
        BUDGET("The AI call limit for this hour or day is used up."),
        OFFLINE("You are offline: cloud AI was skipped."),
        OTHER("The AI request failed.");

        private final String userMessage;

        Kind(String userMessage) {
            this.userMessage = userMessage;
        }

        public String userMessage() {
            return userMessage;
        }
    }

    private final Kind kind;

    public LlmException(String message) {
        this(Kind.OTHER, message);
    }

    public LlmException(String message, Throwable cause) {
        this(Kind.OTHER, message, cause);
    }

    public LlmException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public LlmException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }

    /** The friendly text for the UI. */
    public String userMessage() {
        return kind.userMessage();
    }
}
