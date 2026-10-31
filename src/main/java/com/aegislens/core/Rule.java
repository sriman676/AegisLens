package com.aegislens.core;

/** A yes/no test on one item, for example "does this URL contain a SQL injection pattern". Generic interface. */
public interface Rule<T> {

    String id();

    boolean matches(T item);
}
