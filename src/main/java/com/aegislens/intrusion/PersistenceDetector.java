package com.aegislens.intrusion;

import com.aegislens.core.Finding;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Sysmon events 11 and 13: ways a program makes itself start again after a reboot (persistence).
 * HOST-007 a file created in a Startup folder; HOST-008 a value set under a Run/RunOnce registry key;
 * HOST-009 a new or changed service program (ImagePath), scored higher when it points into a user folder.
 */
public class PersistenceDetector extends HostDetector {

    public static final String STARTUP_RULE = "HOST-007";
    public static final String RUN_KEY_RULE = "HOST-008";
    public static final String SERVICE_RULE = "HOST-009";
    public static final int STARTUP_SCORE = 70;
    public static final int RUN_KEY_SCORE = 65;
    public static final int SERVICE_SCORE = 60;
    public static final int SERVICE_USER_FOLDER_EXTRA = 20;

    private static final String STARTUP_FOLDER = "\\start menu\\programs\\startup\\";
    private static final Pattern RUN_KEY = regex(
            "\\\\software\\\\(wow6432node\\\\)?microsoft\\\\windows\\\\currentversion\\\\(run|runonce|policies\\\\explorer\\\\run)\\\\");
    private static final Pattern SERVICE_PROGRAM = regex("\\\\system\\\\currentcontrolset\\\\services\\\\[^\\\\]{1,200}\\\\imagepath$");

    @Override
    public Set<String> ruleIds() {
        return Set.of(STARTUP_RULE, RUN_KEY_RULE, SERVICE_RULE);
    }

    @Override
    public List<Finding> detect(SysmonEvent e) {
        switch (e.eventId()) {
            case SysmonEvent.FILE_CREATE:
                return startupFile(e);
            case SysmonEvent.REGISTRY_VALUE:
                return registry(e);
            default:
                return List.of();
        }
    }

    private List<Finding> startupFile(SysmonEvent e) {
        String file = e.get("TargetFilename");
        if (!file.toLowerCase(Locale.ROOT).contains(STARTUP_FOLDER)) {
            return List.of();
        }
        return List.of(finding(STARTUP_RULE, e, file, STARTUP_SCORE,
                SysmonEvent.fileName(e.get("Image")) + " put a file in a Startup folder", "program", e.get("Image")));
    }

    private List<Finding> registry(SysmonEvent e) {
        String key = e.get("TargetObject");
        String value = e.get("Details");
        String program = SysmonEvent.fileName(e.get("Image"));
        if (RUN_KEY.matcher(key).find()) {
            return List.of(finding(RUN_KEY_RULE, e, key, RUN_KEY_SCORE, program + " added a program that runs at logon",
                    "runs", value, "program", e.get("Image")));
        }
        if (SERVICE_PROGRAM.matcher(key).find()) {
            int score = SERVICE_SCORE + (inUserFolder(value) ? SERVICE_USER_FOLDER_EXTRA : 0);
            String service = key.substring(0, key.lastIndexOf('\\'));        // the target is the service, not "ImagePath"
            return List.of(finding(SERVICE_RULE, e, service, score, program + " set the program of service "
                    + SysmonEvent.fileName(service), "service program", value, "key", key, "program", e.get("Image")));
        }
        return List.of();
    }
}
