package com.aegislens.intrusion;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;

/**
 * One Sysmon event from a Windows host: when, which event id, which computer, and its named fields (for event 1:
 * Image, CommandLine, ParentImage, User ...). raw keeps a capped copy for evidence. Field values are untrusted text.
 */
public record SysmonEvent(Instant timestamp, int eventId, String computer, Map<String, String> data, String raw) {

    /** Sysmon event ids AegisLens reads (the export command is in the README). */
    public static final int PROCESS_CREATE = 1;
    public static final int NETWORK_CONNECT = 3;
    public static final int FILE_CREATE = 11;
    public static final int REGISTRY_KEY = 12;
    public static final int REGISTRY_VALUE = 13;
    public static final int DNS_QUERY = 22;

    public SysmonEvent {
        data = Map.copyOf(data);                       // immutable: detectors cannot change what others see
    }

    /** One field, or "" when the event does not have it. */
    public String get(String field) {
        return data.getOrDefault(field, "");
    }

    /** The program file name in lower case: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -> "powershell.exe". */
    public static String fileName(String path) {
        int cut = Math.max(path.lastIndexOf('\\'), path.lastIndexOf('/'));
        return path.substring(cut + 1).toLowerCase(Locale.ROOT);
    }
}
