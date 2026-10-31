package com.aegislens.intrusion;

import com.aegislens.core.MalformedLogException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared reading of Windows event exports made with "wevtutil qe ... /f:xml" (Security events and Sysmon events use the
 * same format): many &lt;Event&gt; elements and no single root, so the text is wrapped in &lt;Events&gt; first. The XML
 * parser is hardened against XXE: DOCTYPE is refused, external entities and XInclude are off.
 */
final class EventXml {

    /** Exports larger than this are refused (export fewer events with wevtutil's /c:N). */
    static final long MAX_BYTES = 50L * 1024 * 1024;

    private EventXml() {
    }

    /** Every &lt;Event&gt; element in the export. */
    static List<Element> events(Path file) throws IOException, MalformedLogException {
        if (Files.size(file) > MAX_BYTES) {
            throw new MalformedLogException("event export larger than " + MAX_BYTES / (1024 * 1024) + " MB");
        }
        String xml = decode(Files.readAllBytes(file)).replaceAll("<\\?xml[^>]{0,200}\\?>", "");
        NodeList nodes = parseXml("<Events>" + xml + "</Events>").getElementsByTagName("Event");
        List<Element> events = new ArrayList<>(nodes.getLength());
        for (int i = 0; i < nodes.getLength(); i++) {
            events.add((Element) nodes.item(i));
        }
        return events;
    }

    /** A DocumentBuilder that cannot be tricked into reading files or URLs (XXE) or expanding entity bombs. */
    static DocumentBuilder hardenedBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        f.setNamespaceAware(false);
        return f.newDocumentBuilder();
    }

    /** The &lt;Data Name="..."&gt; values of one event. */
    static Map<String, String> data(Element event) {
        Map<String, String> data = new HashMap<>();
        NodeList items = event.getElementsByTagName("Data");
        for (int i = 0; i < items.getLength(); i++) {
            Element d = (Element) items.item(i);
            if (d.hasAttribute("Name")) {
                data.put(d.getAttribute("Name"), d.getTextContent().strip());
            }
        }
        return data;
    }

    /** System/TimeCreated/@SystemTime (UTC). */
    static Instant timeCreated(Element event) throws MalformedLogException {
        NodeList nodes = event.getElementsByTagName("TimeCreated");
        if (nodes.getLength() == 0) {
            throw new MalformedLogException("event without TimeCreated");
        }
        String text = ((Element) nodes.item(0)).getAttribute("SystemTime");
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException e) {
            throw new MalformedLogException("bad SystemTime: " + text, e);
        }
    }

    /** System/Provider/@Name, for example "Microsoft-Windows-Sysmon" ("" if missing). */
    static String provider(Element event) {
        Node node = event.getElementsByTagName("Provider").item(0);
        return node == null ? "" : ((Element) node).getAttribute("Name");
    }

    /** The text of the first child element with this tag ("" if missing). */
    static String text(Element parent, String tag) {
        Node node = parent.getElementsByTagName(tag).item(0);
        return node == null ? "" : node.getTextContent().strip();
    }

    static String cap(String raw) {
        return raw.length() <= LogSource.RAW_CAP ? raw : raw.substring(0, LogSource.RAW_CAP);
    }

    private static Document parseXml(String xml) throws MalformedLogException, IOException {
        try {
            DocumentBuilder builder = hardenedBuilder();
            builder.setErrorHandler(new DefaultHandler() {      // no stderr noise: every problem becomes an exception
                @Override
                public void error(SAXParseException e) throws SAXException {
                    throw e;
                }
            });
            return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (SAXException | ParserConfigurationException e) {
            throw new MalformedLogException("not a valid wevtutil XML export: " + e.getMessage(), e);
        }
    }

    /** wevtutil output redirected by PowerShell is UTF-16; from cmd it is UTF-8. The byte-order mark tells us which. */
    private static String decode(byte[] bytes) {
        Charset cs = StandardCharsets.UTF_8;
        int skip = 0;
        if (bytes.length >= 2 && (bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xFE) {
            cs = StandardCharsets.UTF_16LE;
            skip = 2;
        } else if (bytes.length >= 2 && (bytes[0] & 0xFF) == 0xFE && (bytes[1] & 0xFF) == 0xFF) {
            cs = StandardCharsets.UTF_16BE;
            skip = 2;
        } else if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xEF && (bytes[1] & 0xFF) == 0xBB && (bytes[2] & 0xFF) == 0xBF) {
            skip = 3;
        }
        return new String(bytes, skip, bytes.length - skip, cs);
    }
}
