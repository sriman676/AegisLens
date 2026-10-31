package com.aegislens.ai;

import com.aegislens.core.Finding;

/** Anything that can explain a finding in plain English: an LLM web API or the offline templates. */
public interface LlmProvider {

    /** Short lower-case id such as "claude", "gemini" or "offline". */
    String name();

    String explain(Finding finding) throws LlmException;
}
