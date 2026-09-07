# frozen_string_literal: true

module Phish
  # IOK ("Indicators of Kit") detection.
  # https://phish.report/docs/iok-rule-reference
  #
  # Unlike the other services here, this one calls no vendor API. It fetches
  # the page itself and evaluates the locally synced rule corpus against it, so
  # a match is evidence that the page is running a known phishing kit.
  #
  # The signal is one-sided. A rule matching says a great deal; no rule
  # matching says almost nothing, because the corpus only covers kits somebody
  # has written a rule for. A clean run therefore returns "unknown" with zero
  # confidence, which the aggregator drops below its threshold, rather than
  # "clean", which would put a vote against every other service behind a page
  # nobody has fingerprinted yet.
  class IokService < BaseService
    # What each kind of rule match reports. A kit fingerprint is evidence of a
    # specific kit rather than a reputation score, so its confidence is high and
    # flat rather than scaled by hit count.
    #
    # An identification rule matching (which website builder a page uses, which
    # landing page template it was cloned from) says nothing about intent, so it
    # is recorded in the details and contributes no verdict at all. Without that
    # distinction a rule like `webflow-website-creator` would report every
    # Webflow site on the internet as phishing.
    OUTCOMES = {
      Iok::Severity::MALICIOUS => { verdict: "phishing", confidence: 0.9 },
      Iok::Severity::SUSPICIOUS => { verdict: "suspicious", confidence: 0.5 },
      Iok::Severity::INFORMATIONAL => { verdict: "unknown", confidence: 0.0 }
    }.freeze

    # Kept for callers that referred to the old flat confidence.
    MATCH_CONFIDENCE = OUTCOMES.dig(Iok::Severity::MALICIOUS, :confidence)

    # Self-imposed, since the requests go to the sites being checked rather
    # than to one vendor. Keeps a bulk check from turning into a burst of
    # outbound traffic from our workers.
    rate_limit :minute, requests: 120, period: 1.minute
    rate_limit :hourly, requests: 3000, period: 1.hour

    def check_domain(domain)
      # Checked before normalising: BaseService#normalize_domain raises
      # NoMethodError on a blank value rather than returning one.
      raise ServiceError, "#{service_name} was given an empty domain" if domain.to_s.strip.blank?

      normalized = normalize_domain(domain)
      raise ServiceError, "#{service_name} could not parse #{domain.inspect}" if normalized.blank?

      check_url("https://#{normalized}")
    end

    def check_url(url)
      normalized = normalize_url(url)
      rules = Iok::RuleSet.current

      return no_indicators_result(normalized) if rules.empty?

      log_info("Checking URL against #{rules.size} indicators: #{normalized}")

      with_rate_limit do
        snapshot = capture(normalized)
        build_verdict(rules, snapshot, normalized)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    private

    def capture(url)
      Iok::PageSnapshot.capture(url, logger: logger)
    rescue Iok::PageSnapshot::BlockedAddress => e
      # Not a transient failure: the address will still be internal on a retry.
      log_error("Refused to fetch", e)
      raise ServiceError, "#{service_name} refused to fetch #{url}"
    rescue Iok::PageSnapshot::FetchError => e
      log_error("Fetch failed", e)
      raise ServiceError, "#{service_name} could not fetch #{url}: #{e.message}"
    end

    # The most severe rule that matched decides the verdict. A page carrying
    # both a kit fingerprint and a website-builder identifier is a kit.
    def build_verdict(rules, snapshot, url)
      matches = rules.matches(snapshot)

      return no_match_result(rules, snapshot, url) if matches.empty?

      severity = Iok::Severity.highest(matches.map(&:effective_severity))
      outcome = OUTCOMES.fetch(severity)

      log_info(
        "Matched #{matches.size} indicator(s) for #{url} at severity #{severity}: " \
        "#{matches.map(&:slug).join(', ')}"
      )

      build_result(
        verdict: outcome[:verdict],
        confidence: outcome[:confidence],
        details: {
          url: url,
          source: "iok",
          severity: severity,
          indicators_evaluated: rules.size,
          matched_indicators: matches.map(&:to_match_summary),
          page: snapshot.summary,
          reason: reason_for(severity, matches)
        }
      )
    end

    def reason_for(severity, matches)
      return "Matched #{matches.size} IOK indicator(s)" unless severity == Iok::Severity::INFORMATIONAL

      "Matched only informational IOK indicator(s), which carry no verdict"
    end

    def no_match_result(rules, snapshot, url)
      build_result(
        verdict: "unknown",
        confidence: 0.0,
        details: {
          url: url,
          source: "iok",
          indicators_evaluated: rules.size,
          matched_indicators: [],
          page: snapshot.summary,
          reason: "No IOK indicator matched"
        }
      )
    end

    # Before the first IokSyncJob run the table is empty. Say so instead of
    # fetching a page that nothing will be evaluated against.
    def no_indicators_result(url)
      log_info("No IOK indicators loaded, skipping #{url}")

      build_result(
        verdict: "unknown",
        confidence: 0.0,
        details: {
          url: url,
          source: "iok",
          indicators_evaluated: 0,
          reason: "No IOK indicators loaded"
        }
      )
    end
  end
end
