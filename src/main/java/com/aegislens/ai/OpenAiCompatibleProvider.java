package com.aegislens.ai;

import com.aegislens.ai.LlmException.Kind;
import com.aegislens.core.Finding;
import com.aegislens.net.RetryPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.HashMap;
import java.util.Map;

/**
 * A locally run model behind an OpenAI-compatible server: POST {baseUrl}/chat/completions. Works with Ollama
 * (http://localhost:11434/v1), LM Studio (http://localhost:1234/v1) and llama.cpp's server. Nothing leaves the
 * machine, so prompts are not redacted. A key is optional (LOCAL_LLM_API_KEY) for servers that want one.
 */
public class OpenAiCompatibleProvider extends HttpLlmProvider {

    static final int MAX_TOKENS = 400;
    static final double TEMPERATURE = 0.2;

    private final String baseUrl;
    private final String model;
    private final String apiKey;

    public OpenAiCompatibleProvider(String baseUrl, String model, String apiKey, HttpClient client, RetryPolicy retry) {
        super(client, retry);
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.model = model;
        this.apiKey = apiKey;
    }

    @Override
    public String name() {
        return "local";
    }

    @Override
    public String explain(Finding finding) throws LlmException {
        if (baseUrl.isBlank() || model == null || model.isBlank()) {
            throw new LlmException(Kind.NOT_CONFIGURED, "No local model address or name configured");
        }
        ObjectNode body = mapper.createObjectNode();
        body.put("model", model);
        body.put("temperature", TEMPERATURE);
        body.put("max_tokens", MAX_TOKENS);
        body.put("stream", false);
        ArrayNode messages = body.putArray("messages");
        messages.addObject().put("role", "system").put("content", "You explain security alerts to a student, briefly and accurately.");
        messages.addObject().put("role", "user").put("content", PromptBuilder.build(finding));
        Map<String, String> headers = new HashMap<>();
        if (apiKey != null && !apiKey.isBlank()) {
            headers.put("authorization", "Bearer " + apiKey);
        }
        return parse(json(post(URI.create(baseUrl + "/chat/completions"), headers, body.toString())));
    }

    String parse(JsonNode reply) throws LlmException {
        JsonNode choice = reply.path("choices").path(0);
        if (choice.path("finish_reason").asText("").equals("content_filter")) {
            throw new LlmException(Kind.BLOCKED, "The local model's filter blocked the answer");
        }
        String text = choice.path("message").path("content").asText("");
        if (text.isBlank()) {
            throw new LlmException(Kind.BAD_RESPONSE, "The local model's reply had no text");
        }
        return text.strip();
    }
}
