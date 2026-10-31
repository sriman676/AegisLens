package com.aegislens.intrusion;

import com.aegislens.core.Finding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Sysmon event 1 (process start), three rules (scores in the README rule table):
 * HOST-001 PowerShell started with an encoded command or several hiding/downloading signs;
 * HOST-002 a Windows tool misused to download or run code (certutil, mshta, rundll32, regsvr32, bitsadmin, wmic);
 * HOST-003 a program started from a user folder (Temp, Downloads, Public, AppData).
 */
public class ProcessStartDetector extends HostDetector {

    public static final String POWERSHELL_RULE = "HOST-001";
    public static final String TOOL_RULE = "HOST-002";
    public static final String USER_FOLDER_RULE = "HOST-003";
    public static final int POWERSHELL_SCORE = 70;
    public static final int POWERSHELL_EXTRA = 10;
    public static final int POWERSHELL_MAX = 90;
    public static final int TOOL_SCORE = 75;
    public static final int USER_FOLDER_SCORE = 40;

    private static final Set<String> POWERSHELL = Set.of("powershell.exe", "pwsh.exe");
    private static final String ENCODED = "encoded command";
    private static final Map<String, Pattern> POWERSHELL_SIGNS = new LinkedHashMap<>();
    private static final Map<String, Pattern> TOOL_MISUSE = new LinkedHashMap<>();

    static {
        POWERSHELL_SIGNS.put(ENCODED, regex("\\s[-/]e[a-z]{0,13}\\s+[a-z0-9+/=]{20,}"));
        POWERSHELL_SIGNS.put("hidden window", regex("\\s[-/]w[a-z]{0,10}\\s+hidden"));
        POWERSHELL_SIGNS.put("download", regex("downloadstring|downloadfile|invoke-webrequest|net\\.webclient|start-bitstransfer|\\biwr\\s"));
        POWERSHELL_SIGNS.put("runs text as code", regex("\\biex\\b|invoke-expression|frombase64string"));
        POWERSHELL_SIGNS.put("policy bypass", regex("[-/]ex[a-z]{0,13}\\s+bypass"));
        TOOL_MISUSE.put("certutil.exe", regex("[-/](urlcache|decode|decodehex)\\b"));
        TOOL_MISUSE.put("mshta.exe", regex("https?:|javascript:|vbscript:"));
        TOOL_MISUSE.put("rundll32.exe", regex("javascript:|https?://"));
        TOOL_MISUSE.put("regsvr32.exe", regex("[-/]i:\\s?https?:|scrobj\\.dll"));
        TOOL_MISUSE.put("bitsadmin.exe", regex("/transfer\\b"));
        TOOL_MISUSE.put("wmic.exe", regex("process\\s+call\\s+create|/format:\\s?https?:"));
    }

    @Override
    public Set<String> ruleIds() {
        return Set.of(POWERSHELL_RULE, TOOL_RULE, USER_FOLDER_RULE);
    }

    @Override
    public List<Finding> detect(SysmonEvent e) {
        List<Finding> found = new ArrayList<>();
        if (e.eventId() != SysmonEvent.PROCESS_CREATE) {
            return found;
        }
        String image = e.get("Image");
        String program = SysmonEvent.fileName(image);
        String command = " " + e.get("CommandLine");
        if (POWERSHELL.contains(program)) {
            powershell(e, image, command, found);
        }
        Pattern misuse = TOOL_MISUSE.get(program);
        if (misuse != null && misuse.matcher(command).find()) {
            found.add(finding(TOOL_RULE, e, image, TOOL_SCORE, program + " used to download or run code",
                    "command", e.get("CommandLine"), "parent", e.get("ParentImage")));
        }
        if (inUserFolder(image)) {
            found.add(finding(USER_FOLDER_RULE, e, image, USER_FOLDER_SCORE, "Program started from a user folder: " + program,
                    "parent", e.get("ParentImage")));
        }
        return found;
    }

    /** One sign is enough only if it is an encoded command; otherwise two signs are needed. */
    private void powershell(SysmonEvent e, String image, String command, List<Finding> found) {
        List<String> signs = new ArrayList<>();
        POWERSHELL_SIGNS.forEach((name, p) -> {
            if (p.matcher(command).find()) {
                signs.add(name);
            }
        });
        if (signs.contains(ENCODED) || signs.size() >= 2) {
            int score = Math.min(POWERSHELL_MAX, POWERSHELL_SCORE + POWERSHELL_EXTRA * (signs.size() - 1));
            found.add(finding(POWERSHELL_RULE, e, image, score, "Suspicious PowerShell: " + String.join(", ", signs),
                    "signs", String.join(", ", signs), "command", e.get("CommandLine"), "parent", e.get("ParentImage")));
        }
    }
}
