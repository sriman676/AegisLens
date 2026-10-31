package com.aegislens.intrusion;

/**
 * Receives one complete log line from a tailer or the syslog listener. The standard consumer
 * (DetectionEngine.consumerFor) parses it, runs the detectors and publishes findings; tests use a list.
 */
@FunctionalInterface
public interface LineConsumer {
    void accept(String line) throws InterruptedException;
}
