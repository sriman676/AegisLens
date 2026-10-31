package com.aegislens.sandbox;

import java.time.Duration;

/**
 * Limits applied to everything the sandbox runs. A Java 16+ record: an immutable data holder with
 * validation in the compact constructor.
 *
 * @param timeout            wall-clock time before the run is killed
 * @param maxOutputBytes     how much stdout/stderr we keep (the rest is read and discarded)
 * @param maxHeapMb          heap limit for the local demo JVM
 * @param containerMemoryMb  memory limit (and swap limit) of the container
 * @param containerCpus      CPU share of the container, for example 0.5
 * @param pidsLimit          maximum processes/threads inside the container (stops fork bombs)
 */
public record SandboxPolicy(Duration timeout, int maxOutputBytes, int maxHeapMb,
                            int containerMemoryMb, double containerCpus, int pidsLimit) {

    public SandboxPolicy {
        if (timeout == null || timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("timeout must be between 1 ms and 5 minutes");
        }
        if (maxOutputBytes < 1024 || maxOutputBytes > 1_048_576) {
            throw new IllegalArgumentException("maxOutputBytes must be 1 KB to 1 MB");
        }
        if (maxHeapMb < 16 || maxHeapMb > 512) {
            throw new IllegalArgumentException("maxHeapMb must be 16 to 512");
        }
        if (containerMemoryMb < 32 || containerMemoryMb > 1024) {
            throw new IllegalArgumentException("containerMemoryMb must be 32 to 1024");
        }
        if (containerCpus <= 0 || containerCpus > 2) {
            throw new IllegalArgumentException("containerCpus must be above 0 and at most 2");
        }
        if (pidsLimit < 8 || pidsLimit > 256) {
            throw new IllegalArgumentException("pidsLimit must be 8 to 256");
        }
    }

    /** Conservative defaults: 10 s, 64 KB of output, 32 MB heap, 128 MB container, half a CPU, 64 processes. */
    public static SandboxPolicy defaults() {
        return new SandboxPolicy(Duration.ofSeconds(10), 64 * 1024, 32, 128, 0.5, 64);
    }

    public SandboxPolicy withTimeout(Duration newTimeout) {
        return new SandboxPolicy(newTimeout, maxOutputBytes, maxHeapMb, containerMemoryMb, containerCpus, pidsLimit);
    }

    public SandboxPolicy withMaxOutputBytes(int newMax) {
        return new SandboxPolicy(timeout, newMax, maxHeapMb, containerMemoryMb, containerCpus, pidsLimit);
    }
}
