package com.aegislens.sandbox;

/**
 * The only programs the LOCAL sandbox will run: harmless demos written by the team that imitate suspicious behaviour.
 * Because this is an enum, the local sandbox cannot be pointed at an arbitrary file.
 */
public enum DemoProgram {
    HELLO("hello", "Prints a greeting and exits normally"),
    DROPPER("dropper", "Creates three files in its working directory, like malware dropping payloads"),
    BURNER("burner", "Spins the CPU forever, like a cryptominer or a hang"),
    CHATTY("chatty", "Floods standard output with about 10 MB"),
    CRASH("crash", "Throws an exception and exits with an error"),
    ENV("env", "Reports whether it can see environment variables such as PATH");

    private final String id;
    private final String description;

    DemoProgram(String id, String description) {
        this.id = id;
        this.description = description;
    }

    public String id() {
        return id;
    }

    public String description() {
        return description;
    }
}
