package com.aegislens.ai;

import com.aegislens.ai.LlmException.Kind;
import com.aegislens.core.Finding;
import com.aegislens.net.RetryPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Map;

/**
 * Calls the Anthropic Messages API (POST /v1/messages) over HTTPS. Reads the reply tolerantly: text
 * blocks are joined, stop_reason "refusal" means BLOCKED, "max_tokens" keeps the partial text with a note, and anything
 * unexpected is BAD_RESPONSE, never a NullPointerException. Model and API version are configurable (N12).
 */
public class ClaudeProvider extends HttpLlmProvider {

    /** Header value for "anthropic-version" (long-standing value; override with claude.api.version or CLAUDE_API_VERSION). */
    public static final String DEFAULT_API_VERSION = "2023-06-01";
    public static final String DEFAULT_URL = "https://api.anthropic.com/v1/messages";
    public static final String DEFAULT_MODEL = "claude-haiku-5-5";
    static final int MAX_TOKENS = 400;

    private final String apiKey;
    private final String model;
    private final String url;
    private final String apiVersion;

    public ClaudeProvider(String apiKey, String model, String url, String apiVersion, HttpClient client, RetryPolicy retry) {
        super(client, retry);
        this.apiKey = apiKey;
        this.model = model;
        this.url = url;
        this.apiVersion = apiVersion;
    }

    public ClaudeProvider(String apiKey, String model, String url) {
        super();
        this.apiKey = apiKey;
        this.model = model;
        this.url = url;
        String v = System.getenv("CLAUDE_API_VERSION");
        this.apiVersion = v == null || v.isBlank() ? DEFAULT_API_VERSION : v.trim();
    }

    public ClaudeProvider(String apiKey) {
        this(apiKey, DEFAULT_MODEL, DEFAULT_URL);
    }

    @Override
    public String name() {
        return "claude";
    }

    public URI endpoint() {
        return URI.create(url);
    }

    @Override
    public String explain(Finding finding) throws LlmException {
        requireKey(apiKey, "Claude");
        ObjectNode body = mapper.createObjectNode();
        body.put("model", model);
        body.put("max_tokens", MAX_TOKENS);
        ArrayNode messages = body.putArray("messages");
        messages.addObject().put("role", "user").put("content", PromptBuilder.build(finding));
        String response = post(URI.create(url), Map.of("x-api-key", apiKey, "anthropic-version", apiVersion), body.toString());
        return parse(json(response));
    }

    String parse(JsonNode reply) throws LlmException {
        String stop = reply.path("stop_reason").asText("");
        if (stop.equals("refusal")) {
            throw new LlmException(Kind.BLOCKED, "Claude declined to answer");
        }
        StringBuilder text = new StringBuilder();
        for (JsonNode block : reply.path("content")) {
            if (block.path("type").asText("text").equals("text")) {
                text.append(block.path("text").asText(""));
            }
        }
        if (text.toString().isBlank()) {
            throw new LlmException(Kind.BAD_RESPONSE, "Claude reply had no text");
        }
        if (stop.equals("max_tokens")) {
            text.append("\n\n(The answer was cut short at the length limit.)");
        }
        return text.toString().strip();
    }
}
