package com.aegislens.core;

import java.util.List;

/** Looks at one event and returns findings, for example a log line. Generic interface. */
public interface Detector<T> {

    List<Finding> detect(T event);
}
