package com.aegislens.net;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/**
 * A response body handler that reads at most maxBytes and then cancels the download, so a hostile or
 * broken server cannot fill our memory. LLM replies use 1 MB, feeds 20 MB. A Content-Length above the limit fails
 * before any byte is read., byte buffers.
 */
public final class BoundedBody {

    public static final long LLM_LIMIT = 1024 * 1024;
    public static final long FEED_LIMIT = 20L * 1024 * 1024;

    private BoundedBody() {
    }

    /** A handler producing the body as UTF-8 text, or failing with ResponseTooLargeException. */
    public static HttpResponse.BodyHandler<String> ofString(long maxBytes) {
        return info -> {
            long declared = info.headers().firstValueAsLong("content-length").orElse(-1);
            if (declared > maxBytes) {
                return HttpResponse.BodySubscribers.replacing(null);
            }
            return new Subscriber(maxBytes);
        };
    }

    /** True if the handler above returned null because of a declared Content-Length over the limit. */
    public static void requireBody(HttpResponse<String> response, long maxBytes) throws ResponseTooLargeException {
        if (response.body() == null) {
            throw new ResponseTooLargeException(maxBytes);
        }
    }

    private static final class Subscriber implements HttpResponse.BodySubscriber<String> {
        private final long max;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final CompletableFuture<String> result = new CompletableFuture<>();
        private Flow.Subscription subscription;

        Subscriber(long max) {
            this.max = max;
        }

        @Override
        public CompletionStage<String> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            subscription = s;
            s.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            for (ByteBuffer b : items) {
                if (buffer.size() + (long) b.remaining() > max) {
                    subscription.cancel();
                    result.completeExceptionally(new ResponseTooLargeException(max));
                    return;
                }
                byte[] chunk = new byte[b.remaining()];
                b.get(chunk);
                buffer.writeBytes(chunk);
            }
        }

        @Override
        public void onError(Throwable t) {
            result.completeExceptionally(t);
        }

        @Override
        public void onComplete() {
            result.complete(buffer.toString(StandardCharsets.UTF_8));
        }
    }
}
