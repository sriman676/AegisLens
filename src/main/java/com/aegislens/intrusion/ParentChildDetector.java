package com.aegislens.intrusion;

import com.aegislens.core.Finding;

import java.util.List;
import java.util.Set;

/**
 * Sysmon event 1, HOST-004: an Office program, PDF reader or web browser started a shell or script host. That is how
 * malicious documents and drive-by downloads usually start; normal use almost never does it. Office/PDF parents score
 * higher than browsers (the README rule table).
 */
public class ParentChildDetector extends HostDetector {

    public static final String RULE = "HOST-004";
    public static final int DOCUMENT_SCORE = 80;
    public static final int BROWSER_SCORE = 60;

    static final Set<String> DOCUMENT_APPS = Set.of("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe", "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe");
    static final Set<String> BROWSERS = Set.of("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe",
            "opera.exe");
    static final Set<String> SHELLS = Set.of("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe");

    @Override
    public Set<String> ruleIds() {
        return Set.of(RULE);
    }

    @Override
    public List<Finding> detect(SysmonEvent e) {
        if (e.eventId() != SysmonEvent.PROCESS_CREATE) {
            return List.of();
        }
        String parent = SysmonEvent.fileName(e.get("ParentImage"));
        String child = SysmonEvent.fileName(e.get("Image"));
        if (!SHELLS.contains(child)) {
            return List.of();
        }
        int score = DOCUMENT_APPS.contains(parent) ? DOCUMENT_SCORE : BROWSERS.contains(parent) ? BROWSER_SCORE : 0;
        if (score == 0 || (score == BROWSER_SCORE && nativeMessaging(e))) {
            return List.of();
        }
        return List.of(finding(RULE, e, e.get("Image"), score, parent + " started " + child,
                "parent", e.get("ParentImage"), "command", e.get("CommandLine")));
    }

    /**
     * Chrome and Edge start a browser extension's helper ("native messaging host") through cmd.exe with the extension's
     * address as an argument: "cmd.exe /d /s /c "host.bat" chrome-extension://&lt;id&gt;/ ...". Normal, so not reported
     * (found on real Sysmon data from the Claude-in-Chrome extension).
     */
    private static boolean nativeMessaging(SysmonEvent e) {
        return SysmonEvent.fileName(e.get("Image")).equals("cmd.exe") && e.get("CommandLine").contains(" chrome-extension://");
    }
}
