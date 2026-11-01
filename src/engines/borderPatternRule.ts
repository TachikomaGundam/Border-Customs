// Vendored from @secretlint/secretlint-rule-pattern@13.0.5 — MIT License,
// Copyright (c) 2017-2024 azu / secretlint contributors (full text: that
// package's LICENSE). Trimmed to the exact option surface border compiles
// (content patterns + allows); micromatch was reached ONLY for filePathGlobs,
// which border never emits, so the glob dependency — the carrier of three
// unpatched high advisories (braces/micromatch, audit 2026-10-17) — left the
// production graph with it. filePathGlobs in an option here is REJECTED, not
// silently dropped: dropping a scope filter would broaden what matches.
// The CLI descriptor path (test seam) still names the upstream package, whose
// creator logic and messages this file mirrors verbatim, so both engines'
// rule ids and finding text stay identical.
import { matchPatterns } from "@textlint/regexp-string-matcher";

import type { SecretLintRuleCreator, SecretLintSourceCode } from "@secretlint/types";

export type PatternType = {
  readonly name: string;
  readonly pattern?: string;
  readonly patterns?: readonly string[];
  readonly allows?: readonly string[];
  readonly filePathGlobs?: readonly string[];
};

type PatternRuleOptions = {
  allows?: readonly string[];
  patterns?: readonly PatternType[];
};

export const messages = {
  PATTERN: {
    en: (props: { PATTERN_NAME: string; CREDENTIAL: string }) => `found matching ${props.PATTERN_NAME}: ${props.CREDENTIAL}`,
    ja: (props: { PATTERN_NAME: string; CREDENTIAL: string }) => `${props.PATTERN_NAME}にマッチするパターンが見つかりました: ${props.CREDENTIAL}`,
  },
};

function collectPatterns(patternConfig: PatternType): string[] {
  if (patternConfig.patterns && patternConfig.patterns.length > 0 && patternConfig.pattern) {
    throw new Error(`Pattern "${patternConfig.name}" cannot have both "patterns" and "pattern" specified. Use "patterns" array instead.`);
  }
  if (patternConfig.patterns && patternConfig.patterns.length > 0) {
    return [...patternConfig.patterns];
  }
  if (patternConfig.pattern) {
    return [patternConfig.pattern];
  }
  return [];
}

export const creator: SecretLintRuleCreator<PatternRuleOptions> = {
  messages,
  meta: {
    id: "@secretlint/secretlint-rule-pattern",
    recommended: false,
    type: "scanner",
    supportedContentTypes: ["text"],
  },
  create(context, options) {
    const t = context.createTranslator(messages);
    const normalizedOptions = {
      allows: [...(options.allows ?? [])],
      patterns: [...(options.patterns ?? [])],
    };
    for (const p of normalizedOptions.patterns) {
      const hasPatterns = (p.patterns && p.patterns.length > 0) || p.pattern;
      const hasFilePathGlobs = p.filePathGlobs && p.filePathGlobs.length > 0;
      if (!hasPatterns && !hasFilePathGlobs) {
        throw new Error(`Pattern "${p.name}" must have either "patterns", "pattern" (deprecated), or "filePathGlobs" specified`);
      }
    }
    return {
      file(source: SecretLintSourceCode) {
        for (const p of normalizedOptions.patterns) {
          if (p.filePathGlobs && p.filePathGlobs.length > 0) {
            // See header: border's compiler never emits globs; a caller that
            // does would be silently unscoped — refuse instead of guessing.
            throw new Error(`Pattern "${p.name}" uses filePathGlobs, unsupported by border's vendored pattern rule — refuse to guess the scope`);
          }
          const allPatterns = collectPatterns(p);
          if (allPatterns.length === 0) continue;
          const mergedAllows = [...normalizedOptions.allows, ...(p.allows ?? [])];
          for (const result of matchPatterns(source.content, allPatterns)) {
            const index = result.startIndex ?? 0;
            const match = result.match ?? "";
            const allowed = matchPatterns(match, mergedAllows);
            if (allowed.length > 0) continue;
            context.report({
              message: t("PATTERN", { PATTERN_NAME: p.name, CREDENTIAL: match }),
              range: [index, index + match.length],
            });
          }
        }
      },
    };
  },
};
