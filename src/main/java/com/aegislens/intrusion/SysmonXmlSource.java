package com.aegislens.intrusion;

import com.aegislens.core.MalformedLogException;
import org.w3c.dom.Element;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Reads Sysmon events exported by an administrator with
 * wevtutil qe Microsoft-Windows-Sysmon/Operational /c:5000 /rd:true /f:xml &gt; sysmon.xml
 * Only Sysmon events with the ids the host detectors use are kept (1 process start, 3 network connection, 11 file
 * created, 12/13 registry, 22 DNS query); everything else is skipped. Reading and XXE hardening: {@link EventXml}.
 */
public class SysmonXmlSource {

    public static final String PROVIDER = "Microsoft-Windows-Sysmon";
    static final Set<Integer> SUPPORTED = Set.of(SysmonEvent.PROCESS_CREATE, SysmonEvent.NETWORK_CONNECT,
            SysmonEvent.FILE_CREATE, SysmonEvent.REGISTRY_KEY, SysmonEvent.REGISTRY_VALUE, SysmonEvent.DNS_QUERY);

    /** Parses the supported Sysmon events in the file, oldest first. */
    public List<SysmonEvent> parse(Path file) throws IOException, MalformedLogException {
        List<SysmonEvent> events = new ArrayList<>();
        for (Element event : EventXml.events(file)) {
            int id = eventId(event);
            if (PROVIDER.equals(EventXml.provider(event)) && SUPPORTED.contains(id)) {
                var data = EventXml.data(event);
                events.add(new SysmonEvent(EventXml.timeCreated(event), id, EventXml.text(event, "Computer"), data,
                        EventXml.cap("Sysmon " + id + " " + data)));
            }
        }
        events.sort((a, b) -> a.timestamp().compareTo(b.timestamp()));   // /rd:true exports newest first
        return events;
    }

    private static int eventId(Element event) throws MalformedLogException {
        String text = EventXml.text(event, "EventID");
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new MalformedLogException("bad EventID: " + text, e);
        }
    }
}
