package com.aegislens.intrusion;

import com.aegislens.core.MalformedLogException;
import com.aegislens.intrusion.LogEvent.Action;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Reads Windows Security events exported by the admin with
 * wevtutil qe Security "/q:*[System[(EventID=4624 or EventID=4625 or EventID=4740)]]" /f:xml &gt; security.xml
 * Reading and XXE hardening are shared with the Sysmon reader ({@link EventXml}).
 * 4625 = failed logon, 4624 = successful logon (detail = logon type), 4740 = account locked out.
 */
public class WindowsEventXmlSource {

    public static final long MAX_BYTES = EventXml.MAX_BYTES;
    private static final String SOURCE = "windows";

    /** Parses every supported event in the file; other event ids are skipped. */
    public List<LogEvent> parse(Path file) throws IOException, MalformedLogException {
        List<LogEvent> events = new ArrayList<>();
        for (Element event : EventXml.events(file)) {
            LogEvent e = toEvent(event);
            if (e != null) {
                events.add(e);
            }
        }
        return events;
    }

    private static LogEvent toEvent(Element event) throws MalformedLogException {
        String id = EventXml.text(event, "EventID");
        Map<String, String> data = EventXml.data(event);
        Instant ts = EventXml.timeCreated(event);
        String raw = EventXml.cap("EventID " + id + " " + data);
        String user = data.get("TargetUserName");
        String ip = data.get("IpAddress");
        if (ip != null && (ip.equals("-") || ip.isBlank())) {
            ip = null;
        }
        switch (id) {
            case "4625":
                return LogEvent.login(ts, SOURCE, ip, user, Action.FAILED_LOGIN, "status " + data.get("Status"), raw);
            case "4624":
                return LogEvent.login(ts, SOURCE, ip, user, Action.SUCCESS_LOGIN, "logon type " + data.get("LogonType"), raw);
            case "4740":
                return LogEvent.login(ts, SOURCE, ip, user, Action.ACCOUNT_LOCKOUT, null, raw);
            default:
                return null;
        }
    }
}
