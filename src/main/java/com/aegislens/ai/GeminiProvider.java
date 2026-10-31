package com.aegislens.ai;

import com.aegislens.ai.LlmException.Kind;
import com.aegislens.core.Finding;
import com.aegislens.net.RetryPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Map;

/**
 * Calls the Google Gemini REST API (POST /v1beta/models/{model}:generateContent) over HTTPS; the key goes in the
 * x-goog-api-key header. Reads the reply tolerantly: no candidates or a blockReason / SAFETY finish means
 * BLOCKED, missing text means BAD_RESPONSE. The model name is configurable (N12). Gemini has a free tier.
 */
public class GeminiProvider extends HttpLlmProvider {

    public static final String DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com";
    public static final String DEFAULT_MODEL = "gemini-3.8-flash";

    private final String apiKey;
    private final String model;
    private final String baseUrl;

    public GeminiProvider(String apiKey, String model, String baseUrl, HttpClient client, RetryPolicy retry) {
        super(client, retry);
        this.apiKey = apiKey;
        this.model = model;
        this.baseUrl = baseUrl;
    }

    public GeminiProvider(String apiKey, String model, String baseUrl) {
        super();
        this.apiKey = apiKey;
        this.model = model;
        this.baseUrl = baseUrl;
    }

    public GeminiProvider(String apiKey) {
        this(apiKey, DEFAULT_MODEL, DEFAULT_BASE_URL);
    }

    @Override
    public String name() {
        return "gemini";
    }

    public URI endpoint() {
        return URI.create(baseUrl + "/");
    }

    @Override
    public String explain(Finding finding) throws LlmException {
        requireKey(apiKey, "Gemini");
        ObjectNode body = mapper.createObjectNode();
        body.putArray("contents").addObject().putArray("parts").addObject().put("text", PromptBuilder.build(finding));
        URI uri = URI.create(baseUrl + "/v1beta/models/" + model + ":generateContent");
        return parse(json(post(uri, Map.of("x-goog-api-key", apiKey), body.toString())));
    }

    String parse(JsonNode reply) throws LlmException {
        if (!reply.path("promptFeedback").path("blockReason").asText("").isEmpty()) {
            throw new LlmException(Kind.BLOCKED, "Gemini blocked the prompt");
        }
        JsonNode candidates = reply.path("candidates");
        if (!candidates.isArray() || candidates.isEmpty()) {
            throw new LlmException(Kind.BLOCKED, "Gemini returned no candidates (usually a safety block)");
        }
        JsonNode first = candidates.get(0);
        if (first.path("finishReason").asText("").equals("SAFETY")) {
            throw new LlmException(Kind.BLOCKED, "Gemini stopped for safety reasons");
        }
        StringBuilder text = new StringBuilder();
        for (JsonNode part : first.path("content").path("parts")) {
            text.append(part.path("text").asText(""));
        }
        if (text.toString().isBlank()) {
            throw new LlmException(Kind.BAD_RESPONSE, "Gemini reply had no text");
        }
        return text.toString().strip();
    }
}
