package com.aegislens.ui;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * UI text from {@code /i18n/messages.properties} through a ResourceBundle (G14), so a translation is one new file. A
 * missing key shows as "!key!" instead of crashing, which makes forgotten keys easy to spot.
 */
public final class Messages {

    private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("i18n.messages", Locale.getDefault());

    private Messages() {
    }

    /** The text for a key. */
    public static String text(String key) {
        try {
            return BUNDLE.getString(key);
        } catch (MissingResourceException e) {
            return "!" + key + "!";
        }
    }

    /** The text for a key with {0}, {1}... filled in. */
    public static String text(String key, Object... args) {
        return MessageFormat.format(text(key).replace("'", "''"), args);
    }
}
