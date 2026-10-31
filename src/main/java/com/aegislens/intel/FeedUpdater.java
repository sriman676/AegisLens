package com.aegislens.intel;

import com.aegislens.db.FeedState;
import com.aegislens.db.FeedStateRepository;
import com.aegislens.db.IocRepository;
import com.aegislens.net.BoundedBody;
import com.aegislens.net.ResponseTooLargeException;
import com.aegislens.net.RetryPolicy;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Keeps the threat-intelligence feeds up to date without ever disturbing the app:
 * checks which enabled feeds are due (default daily, never faster than each feed's minimum), downloads with a
 * conditional GET (ETag / Last-Modified, so an unchanged feed costs one tiny 304), caps the download at 20 MB, retries
 * temporary errors, parses everything BEFORE touching the database, and then replaces that feed's indicators in one
 * transaction. If the result is empty (and the feed is not one where empty is normal) or anything fails, the old data
 * stays and the reason is recorded in feed_state. Nothing here throws to the caller.
 */
public final class FeedUpdater {

    public static final Duration STALE_AFTER = Duration.ofDays(3);
    public static final Duration TIMEOUT = Duration.ofSeconds(30);
    private static final String USER_AGENT = "AegisLens/1.0 (student security workbench)";
    private static final Logger LOG = Logger.getLogger(FeedUpdater.class.getName());

    /** What happened to one feed in one run. */
    public enum Outcome { UPDATED, NOT_MODIFIED, FAILED, SKIPPED }

    public record Result(String feed, Outcome outcome, int entries, String message) {
    }

    /** One line of the feed status (for the UI and logs). */
    public record Status(String feed, boolean enabled, int entries, Instant lastSuccess, boolean stale,
                         String lastError, String attribution) {
    }

    private final List<FeedDefinition> feeds;
    private final HttpClient client;
    private final RetryPolicy retry;
    private final IocRepository iocs;
    private final FeedStateRepository states;
    private final Function<String, String> env;
    private final Clock clock;

    public FeedUpdater(List<FeedDefinition> feeds, HttpClient client, RetryPolicy retry, IocRepository iocs,
                       FeedStateRepository states, Function<String, String> env, Clock clock) {
        this.feeds = List.copyOf(feeds);
        this.client = client;
        this.retry = retry;
        this.iocs = iocs;
        this.states = states;
        this.env = env;
        this.clock = clock;
    }

    /** Updates every enabled feed whose interval has passed. */
    public synchronized List<Result> updateDue() {
        List<Result> results = new ArrayList<>();
        for (FeedDefinition f : feeds) {
            if (f.enabled() && due(f, f.interval())) {
                results.add(update(f));
            }
        }
        return results;
    }

    /** Updates every enabled feed now, except those checked more recently than their minimum interval. */
    public synchronized List<Result> updateAllNow() {
        List<Result> results = new ArrayList<>();
        for (FeedDefinition f : feeds) {
            if (!f.enabled()) {
                continue;
            }
            results.add(due(f, f.minInterval()) ? update(f)
                    : new Result(f.name(), Outcome.SKIPPED, 0, "checked less than " + f.minInterval().toMinutes() + " minutes ago"));
        }
        return results;
    }

    private boolean due(FeedDefinition f, Duration wait) {
        Optional<FeedState> s = state(f);
        return s.isEmpty() || s.get().lastChecked() == null || !clock.instant().isBefore(s.get().lastChecked().plus(wait));
    }

    /** Downloads, parses and stores one feed. Never throws. */
    Result update(FeedDefinition f) {
        Instant now = clock.instant();
        FeedState old = state(f).orElse(new FeedState(f.name(), f.url().toString(), null, null, null, null, 0, null));
        try {
            HttpResponse<String> r = retry.execute(() -> client.send(request(f, old), BoundedBody.ofString(BoundedBody.FEED_LIMIT)));
            if (r.statusCode() == 304) {
                save(new FeedState(f.name(), f.url().toString(), now, now, old.etag(), old.lastModified(), old.entries(), null));
                return new Result(f.name(), Outcome.NOT_MODIFIED, old.entries(), "unchanged");
            }
            BoundedBody.requireBody(r, BoundedBody.FEED_LIMIT);
            if (r.statusCode() / 100 != 2) {
                return fail(f, old, now, "HTTP " + r.statusCode());
            }
            Set<String> values = FeedParsers.parse(f, r.body());
            if (values.isEmpty() && !f.allowEmpty()) {
                return fail(f, old, now, "zero entries (did the format change?); kept the previous data");
            }
            int stored = iocs.replaceSource(f.kind(), f.source(), values);
            save(new FeedState(f.name(), f.url().toString(), now, now, r.headers().firstValue("etag").orElse(null),
                    r.headers().firstValue("last-modified").orElse(null), stored, null));
            LOG.info("Feed " + f.name() + " updated: " + stored + " entries");
            return new Result(f.name(), Outcome.UPDATED, stored, stored + " entries");
        } catch (ResponseTooLargeException e) {
            return fail(f, old, now, "download larger than 20 MB; kept the previous data");
        } catch (IOException e) {
            return fail(f, old, now, "could not download (" + e.getClass().getSimpleName() + "); working offline with the previous data");
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Saving feed " + f.name() + " failed", e);
            return fail(f, old, now, "database error while saving");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(f.name(), Outcome.FAILED, old.entries(), "interrupted");
        }
    }

    private HttpRequest request(FeedDefinition f, FeedState old) {
        HttpRequest.Builder b = HttpRequest.newBuilder(f.url()).timeout(TIMEOUT).header("user-agent", USER_AGENT).GET();
        if (old.etag() != null) {
            b.header("if-none-match", old.etag());
        }
        if (old.lastModified() != null) {
            b.header("if-modified-since", old.lastModified());
        }
        if (f.headerName() != null && f.headerEnv() != null) {
            String value = env.apply(f.headerEnv());
            if (value != null && !value.isBlank()) {
                b.header(f.headerName(), value.trim());
            }
        }
        return b.build();
    }

    private Result fail(FeedDefinition f, FeedState old, Instant now, String why) {
        save(new FeedState(f.name(), f.url().toString(), now, old.lastSuccess(), old.etag(), old.lastModified(), old.entries(), why));
        LOG.warning("Feed " + f.name() + ": " + why);
        return new Result(f.name(), Outcome.FAILED, old.entries(), why);
    }

    private Optional<FeedState> state(FeedDefinition f) {
        try {
            return states.get(f.name());
        } catch (SQLException e) {
            return Optional.empty();
        }
    }

    private void save(FeedState s) {
        try {
            states.save(s);
        } catch (SQLException e) {
            LOG.log(Level.WARNING, "Could not save feed state for " + s.name(), e);
        }
    }

    /** Every configured feed with its entries, freshness and last error. */
    public List<Status> status() {
        List<Status> list = new ArrayList<>();
        Instant now = clock.instant();
        for (FeedDefinition f : feeds) {
            Optional<FeedState> s = state(f);
            Instant ok = s.map(FeedState::lastSuccess).orElse(null);
            boolean stale = f.enabled() && (ok == null || ok.isBefore(now.minus(STALE_AFTER)));
            list.add(new Status(f.name(), f.enabled(), s.map(FeedState::entries).orElse(0), ok, stale,
                    s.map(FeedState::lastError).orElse(null), f.attribution()));
        }
        return list;
    }

    public List<FeedDefinition> feeds() {
        return feeds;
    }
}
