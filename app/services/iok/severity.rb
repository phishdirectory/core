# frozen_string_literal: true

module Iok
  # What a rule matching actually means.
  #
  # Not every IOK rule is a phishing verdict. The corpus carries three kinds of
  # rule, and treating them alike produces false positives:
  #
  #   * Kit and malware fingerprints. A match is the kit. These are the
  #     majority, and they mean phishing.
  #   * Technique rules: cloaking, anti-analysis, site cloning. A match says the
  #     page is doing something evasive, which is a reason to look, not a
  #     verdict. `fake-404-page` is one of these.
  #   * Identification rules: which website builder or template a page was
  #     built with. `webflow-website-creator` matches every Webflow site there
  #     is. These carry no verdict at all.
  #
  # Only one rule in the corpus of 266 sets `level`, so the tag namespace does
  # nearly all the work here. Rules that say nothing either way are kits with
  # an incomplete tag list, so the default is malicious.
  module Severity
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    INFORMATIONAL = "informational"

    ALL = [ MALICIOUS, SUSPICIOUS, INFORMATIONAL ].freeze

    RANK = { INFORMATIONAL => 0, SUSPICIOUS => 1, MALICIOUS => 2 }.freeze

    # Sigma's own levels, plus the one value the corpus actually uses.
    LEVELS = {
      "critical" => MALICIOUS,
      "high" => MALICIOUS,
      "malicious" => MALICIOUS,
      "medium" => SUSPICIOUS,
      "potentially_malicious" => SUSPICIOUS,
      "suspicious" => SUSPICIOUS,
      "low" => INFORMATIONAL,
      "informational" => INFORMATIONAL
    }.freeze

    # Matched against the first segment of a tag, so `malware.amadey` counts as
    # `malware`.
    #
    # Tags absent from here describe what a rule is about rather than how bad it
    # is, and fall through to the default. `page_type` is one of them, and is
    # the reason this list is worth stating carefully: it says which kind of
    # page a rule matches, not who built it. `facebook-54b8f7e-landing` carries
    # only `page_type.landing` and `target.facebook`, and it is a Facebook
    # credential kit. Treating `page_type` as an identification tag silently
    # demoted it out of the scoring.
    #
    # The informational tags all name benign tooling: which website builder or
    # template service produced the page. Those match honest sites by design.
    TAGS = {
      MALICIOUS => %w[kit malware crypto_drainer scam threat_actor exfiltration].freeze,
      SUSPICIOUS => %w[anti-analysis cloaking cloning].freeze,
      INFORMATIONAL => %w[website_builder template_service].freeze
    }.freeze

    class << self
      # @param level [String, nil] the rule's `level:` field
      # @param tags [Array<String>] the rule's `tags:` list
      # @return [String] one of ALL
      def derive(level:, tags:)
        from_level(level) || from_tags(tags) || MALICIOUS
      end

      # @param severities [Array<String>]
      # @return [String, nil] the most severe, or nil if none were given
      def highest(severities)
        severities.compact.max_by { |severity| rank(severity) }
      end

      def rank(severity)
        RANK.fetch(severity, RANK[MALICIOUS])
      end

      def valid?(severity)
        ALL.include?(severity)
      end

      private

      def from_level(level)
        LEVELS[level.to_s.strip.downcase.presence]
      end

      # A rule tagged both `kit` and `cloaking` is a kit that also cloaks, so
      # the most severe tag wins rather than the last one read.
      def from_tags(tags)
        namespaces = Array(tags).map { |tag| tag.to_s.split(".").first.to_s.downcase }

        matched = TAGS.filter_map do |severity, known|
          severity if namespaces.intersect?(known)
        end

        highest(matched)
      end
    end
  end
end
