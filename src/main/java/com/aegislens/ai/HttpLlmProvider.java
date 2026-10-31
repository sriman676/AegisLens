package com.aegislens.ai;

import com.aegislens.ai.LlmException.Kind;
import com.aegislens.net.BoundedBody;
import com.aegislens.net.ResponseTooLargeException;
import com.aegislens.net.RetryPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;

/**
 * Shared HTTP code for providers that call a web API: the app's one HttpClient, a 1 MB answer limit, retries for
 * temporary failures, and a typed LlmException for everything else (401 = AUTH, 404 = MODEL_NOT_FOUND, 429 = RATE_LIMIT,
 * 5xx = SERVER, timeouts, network and certificate problems). Error messages never contain the key or the reply body.
 */
abstract class HttpLlmProvider implements LlmProvider {

    public static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(20);
    private static HttpClient fallbackClient;

    protected final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client;
    private final RetryPolicy retry;

    /** Standalone use (tests, old code): a private client and the standard retry policy. */
    protected HttpLlmProvider() {
        this(fallbackClient(), RetryPolicy.standard());
    }

    protected HttpLlmProvider(HttpClient client, RetryPolicy retry) {
        this.client = client;
        this.retry = retry;
    }

    private static synchronized HttpClient fallbackClient() {
        if (fallbackClient == null) {
            fallbackClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }
        return fallbackClient;
    }

    /** POSTs JSON and returns the response body, or throws a typed LlmException. */
    protected String post(URI uri, Map<String, String> headers, String json) throws LlmException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(REQUEST_TIMEOUT)
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json));
        headers.forEach(request::header);
        return send(request.build());
    }

    /** GETs and returns the response body, or throws a typed LlmException. */
    protected String get(URI uri, Map<String, String> headers) throws LlmException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(REQUEST_TIMEOUT).GET();
        headers.forEach(request::header);
        return send(request.build());
    }

    private String send(HttpRequest request) throws LlmException {
        try {
            HttpResponse<String> response = retry.execute(() -> client.send(request, BoundedBody.ofString(BoundedBody.LLM_LIMIT)));
            BoundedBody.requireBody(response, BoundedBody.LLM_LIMIT);
            int status = response.statusCode();
            if (status / 100 != 2) {
                throw new LlmException(kindFor(status), name() + " returned HTTP " + status);
            }
            return response.body();
        } catch (ResponseTooLargeException e) {
            throw new LlmException(Kind.BAD_RESPONSE, name() + " sent a reply larger than 1 MB", e);
        } catch (HttpTimeoutException e) {
            throw new LlmException(Kind.TIMEOUT, name() + " did not answer in time", e);
        } catch (IOException e) {
            throw new LlmException(Kind.NETWORK, name() + " could not be reached (" + e.getClass().getSimpleName() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LlmException(Kind.NETWORK, name() + " request was interrupted", e);
        }
    }

    static Kind kindFor(int status) {
        if (status == 401 || status == 403) {
            return Kind.AUTH;
        }
        if (status == 404) {
            return Kind.MODEL_NOT_FOUND;
        }
        if (status == 429) {
            return Kind.RATE_LIMIT;
        }
        return status >= 500 ? Kind.SERVER : Kind.OTHER;
    }

    /** Parses a reply; anything that is not JSON becomes BAD_RESPONSE (never an exception from deep inside). */
    protected JsonNode json(String body) throws LlmException {
        try {
            JsonNode node = mapper.readTree(body);
            if (node == null || !node.isObject()) {
                throw new LlmException(Kind.BAD_RESPONSE, name() + " reply was not a JSON object");
            }
            return node;
        } catch (IOException e) {
            throw new LlmException(Kind.BAD_RESPONSE, name() + " reply was not valid JSON", e);
        }
    }

    protected static void requireKey(String apiKey, String provider) throws LlmException {
        if (apiKey == null || apiKey.isBlank()) {
            throw new LlmException(Kind.NOT_CONFIGURED, "No API key set for " + provider);
        }
    }
}
