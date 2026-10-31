package com.aegislens.ui;

import com.aegislens.core.Finding;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** G5: the live feed hands over findings in bounded batches and caps a flood. */
class FindingsFeedTest {

    @Test
    void drainsInBatchesOldestFirst() {
        FindingsFeed feed = new FindingsFeed();
        for (int i = 0; i < FindingsFeed.BATCH + 5; i++) {
            feed.offer(finding(i));
        }
        List<Finding> first = feed.drain();
        assertEquals(FindingsFeed.BATCH, first.size());
        assertEquals("f0", first.get(0).description());
        assertEquals(5, feed.drain().size());
        assertTrue(feed.drain().isEmpty());
        assertEquals(0, feed.dropped());
    }

    @Test
    void aFloodFromManyThreadsIsCappedAndCounted() throws InterruptedException {
        FindingsFeed feed = new FindingsFeed();
        List<Thread> writers = new ArrayList<>();
        for (int t = 0; t < 4; t++) {
            Thread w = new Thread(() -> {
                for (int i = 0; i < 5_000; i++) {
                    feed.offer(finding(i));
                }
            });
            writers.add(w);
            w.start();
        }
        for (Thread w : writers) {
            w.join();
        }
        int shown = 0;
        List<Finding> batch;
        while (!(batch = feed.drain()).isEmpty()) {
            shown += batch.size();
        }
        assertEquals(FindingsFeed.MAX_QUEUED, shown, "at most MAX_QUEUED wait for the table");
        assertEquals(20_000 - FindingsFeed.MAX_QUEUED, feed.dropped(), "every finding is either shown or counted");
    }

    private static Finding finding(int i) {
        return new Finding("ssh", "203.0.113.1", "NET-001", 70, "f" + i);
    }
}
