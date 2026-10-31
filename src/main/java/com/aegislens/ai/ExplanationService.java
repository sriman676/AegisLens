package com.aegislens.ai;

import com.aegislens.ai.LlmException.Kind;
import com.aegislens.core.Finding;
import com.aegislens.net.HttpClientFactory;
import com.aegislens.net.RetryPolicy;

import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

/**
 * Gives every finding an explanation, whatever the network does. In AUTO mode it walks the tiers in order:
 * cloud (Claude, Gemini) -> local model -> offline templates, plus SplitShield-XAI context when configured.
 * For each provider call: answer from the cache if known; skip cloud at once when offline; respect the budget;
 * redact private values for cloud; retries happen inside the provider; a typed failure moves on to the next tier.
 * The UI always gets text, never an exception. Providers live in a Hashtable.
 */
public class ExplanationService {

    public static final String AUTO = "auto";
    public static final String CONTEXT_HEADING = "\n\nContext from SplitShield-XAI:\n";

    /** Where a provider sits in the fallback order. */
    public enum Tier { CLOUD, LOCAL, CONTEXT, OFFLINE }

    /** What the UI shows. error is the user message of the last failure (null if none). */
    public record Explanation(String provider, String text, boolean fellBack, boolean cached, boolean redacted, String error) {

        public Explanation(String provider, String text, boolean fellBack) {
            this(provider, text, fellBack, false, false, null);
        }
    }

    private record Answer(String text, boolean cached, boolean redacted) {
    }

    private final Hashtable<String, LlmProvider> providers = new Hashtable<>();
    private final Hashtable<String, Tier> tiers = new Hashtable<>();
    private final List<String> order = new ArrayList<>();
    private final OfflineProvider offline = new OfflineProvider();
    private final List<URI> cloudHosts = new ArrayList<>();
    private volatile BooleanSupplier online = () -> true;
    private volatile ExplanationCache cache = ExplanationCache.NONE;
    private volatile LlmBudget budget = LlmBudget.unlimited();
    private volatile boolean redactCloud = true;

    public ExplanationService() {
        register(offline, Tier.OFFLINE);
    }

    /** Claude and Gemini from their environment keys only (kept for simple setups and old code). */
    public static ExplanationService fromEnvironment() {
        return configured(k -> null, System::getenv, null, RetryPolicy.standard());
    }

    /**
     * Everything from configuration: cloud keys from the environment, local model and SplitShield from config,
     * budget and redaction switches. http may be null (then providers use a private client).
     */
    public static ExplanationService configured(Function<String, String> config, Function<String, String> env,
                                                HttpClientFactory http, RetryPolicy retry) {
        ExplanationService s = new ExplanationService();
        String claudeKey = env.apply("CLAUDE_API_KEY");
        if (present(claudeKey)) {
            ClaudeProvider claude = http == null
                    ? new ClaudeProvider(claudeKey, or(config, env, "claude.model", "CLAUDE_MODEL", ClaudeProvider.DEFAULT_MODEL), ClaudeProvider.DEFAULT_URL)
                    : new ClaudeProvider(claudeKey, or(config, env, "claude.model", "CLAUDE_MODEL", ClaudeProvider.DEFAULT_MODEL),
                    ClaudeProvider.DEFAULT_URL, or(config, env, "claude.api.version", "CLAUDE_API_VERSION", ClaudeProvider.DEFAULT_API_VERSION),
                    http.client(), retry);
            s.register(claude, Tier.CLOUD);
            s.cloudHosts.add(claude.endpoint());
        }
        String geminiKey = env.apply("GEMINI_API_KEY");
        if (present(geminiKey)) {
            String model = or(config, env, "gemini.model", "GEMINI_MODEL", GeminiProvider.DEFAULT_MODEL);
            GeminiProvider gemini = http == null ? new GeminiProvider(geminiKey, model, GeminiProvider.DEFAULT_BASE_URL)
                    : new GeminiProvider(geminiKey, model, GeminiProvider.DEFAULT_BASE_URL, http.client(), retry);
            s.register(gemini, Tier.CLOUD);
            s.cloudHosts.add(gemini.endpoint());
        }
        String localUrl = config.apply("local.llm.url");
        if (present(localUrl) && http != null) {
            s.register(new OpenAiCompatibleProvider(localUrl.trim(), or(config, env, "local.llm.model", "LOCAL_LLM_MODEL", "llama3.2:3b"),
                    env.apply("LOCAL_LLM_API_KEY"), http.client(), RetryPolicy.none()), Tier.LOCAL);
        }
        String splitUrl = config.apply("splitshield.url");
        String pin = config.apply("splitshield.cert.sha256");
        if (present(splitUrl) && http != null) {
            s.register(new SplitShieldProvider(splitUrl.trim(), env.apply("SPLITSHIELD_TOKEN"),
                    present(pin) ? http.pinnedClient(pin.trim()) : http.client(), RetryPolicy.none()), Tier.CONTEXT);
        }
        s.budget = new LlmBudget(intOr(config.apply("ai.budget.hour"), LlmBudget.DEFAULT_PER_HOUR),
                intOr(config.apply("ai.budget.day"), LlmBudget.DEFAULT_PER_DAY), Clock.systemUTC());
        s.redactCloud = !"false".equalsIgnoreCase(String.valueOf(config.apply("ai.redact.cloud")));
        return s;
    }

    public void register(LlmProvider provider) {
        register(provider, switch (provider.name()) {
            case "offline" -> Tier.OFFLINE;
            case "local" -> Tier.LOCAL;
            case "splitshield" -> Tier.CONTEXT;
            default -> Tier.CLOUD;
        });
    }

    public void register(LlmProvider provider, Tier tier) {
        if (!providers.containsKey(provider.name())) {
            order.add(provider.name());
        }
        providers.put(provider.name(), provider);
        tiers.put(provider.name(), tier);
    }

    /** Provider names in fallback order (offline is always there). */
    public List<String> providerNames() {
        List<String> names = new ArrayList<>();
        for (Tier t : Tier.values()) {
            for (String n : order) {
                if (tiers.get(n) == t) {
                    names.add(n);
                }
            }
        }
        return names;
    }

    /** The cloud endpoints, for the connectivity monitor. */
    public List<URI> cloudHosts() {
        return List.copyOf(cloudHosts);
    }

    public void setOnline(BooleanSupplier online) {
        this.online = online;
    }

    public void setCache(ExplanationCache cache) {
        this.cache = cache;
    }

    public void setBudget(LlmBudget budget) {
        this.budget = budget;
    }

    public void setRedactCloud(boolean redactCloud) {
        this.redactCloud = redactCloud;
    }

    public LlmBudget.Usage budgetUsage() {
        return budget.usage();
    }

    /** choice is AUTO or a provider name; an unknown name means the offline templates. */
    public Explanation explain(String choice, Finding finding) {
        if (AUTO.equals(choice)) {
            return auto(finding);
        }
        LlmProvider chosen = providers.get(choice);
        if (chosen == null || chosen == offline) {
            return new Explanation(offline.name(), offline.explain(finding), chosen == null && !"offline".equals(choice));
        }
        try {
            Answer a = call(chosen, finding);
            return new Explanation(chosen.name(), a.text(), false, a.cached(), a.redacted(), null);
        } catch (LlmException e) {
            return new Explanation(offline.name(), offline.explain(finding), true, false, false, e.userMessage());
        }
    }

    private Explanation auto(Finding finding) {
        String lastError = null;
        boolean tried = false;
        for (Tier tier : new Tier[] {Tier.CLOUD, Tier.LOCAL}) {
            for (String name : order) {
                if (tiers.get(name) != tier) {
                    continue;
                }
                tried = true;
                try {
                    Answer a = call(providers.get(name), finding);
                    return new Explanation(name, a.text(), false, a.cached(), a.redacted(), null);
                } catch (LlmException e) {
                    lastError = name + ": " + e.userMessage();
                }
            }
        }
        Optional<String> context = context(finding);
        String text = offline.explain(finding) + context.map(c -> CONTEXT_HEADING + c).orElse("");
        return new Explanation(context.isPresent() ? "offline+splitshield" : "offline", text, tried, false, false, lastError);
    }

    /** SplitShield's view of the finding's IP/user/file, if it is configured and reachable. */
    public Optional<String> context(Finding finding) {
        for (String name : order) {
            if (tiers.get(name) == Tier.CONTEXT) {
                try {
                    return Optional.of(providers.get(name).explain(finding));
                } catch (LlmException ignored) {
                    // context is optional: the explanation works without it
                }
            }
        }
        return Optional.empty();
    }

    private Answer call(LlmProvider p, Finding finding) throws LlmException {
        Tier tier = tiers.get(p.name());
        boolean cloud = tier == Tier.CLOUD;
        if (cloud && !online.getAsBoolean()) {
            throw new LlmException(Kind.OFFLINE, p.name() + " skipped: offline");
        }
        if (finding.id() > 0) {
            Optional<String> known = cache.find(finding.id(), p.name());
            if (known.isPresent()) {
                return new Answer(known.get(), true, false);
            }
        }
        if (cloud && !budget.tryAcquire()) {
            throw new LlmException(Kind.BUDGET, "AI call limit reached");
        }
        Redactor redactor = cloud && redactCloud ? new Redactor() : null;
        Finding sent = redactor == null ? finding : redactor.redact(finding);
        String text = p.explain(sent);
        if (redactor != null) {
            text = redactor.restore(text);
        }
        if (finding.id() > 0 && tier != Tier.CONTEXT) {
            cache.store(finding.id(), p.name(), text);
        }
        return new Answer(text, false, redactor != null && redactor.changedAnything());
    }

    private static boolean present(String s) {
        return s != null && !s.isBlank();
    }

    private static String or(Function<String, String> config, Function<String, String> env, String key, String envName, String fallback) {
        String v = config.apply(key);
        if (present(v)) {
            return v.trim();
        }
        v = env.apply(envName);
        return present(v) ? v.trim() : fallback;
    }

    private static int intOr(String text, int fallback) {
        try {
            return text == null ? fallback : Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

}
