# frozen_string_literal: true

module Phish
  # Hybrid Analysis (Falcon Sandbox) Public API v2
  # https://hybrid-analysis.com/docs/api/v2
  #
  # We use the search endpoint only. It answers "which sandbox reports mention
  # this indicator", which every account level can call. Submitting samples or
  # URLs for a new scan needs an elevated key, and a restricted key gets 403
  # for it, so this service never submits.
  #
  # Rate Limits (restricted self-signed key, the level a free account starts at):
  #   5 requests per minute
  #   200 requests per hour
  #
  # Report verdicts: malicious, suspicious, no specific threat, whitelisted.
  # A report can also carry no verdict at all, which we count as unknown.
  #
  # Because of the per minute limit this service is not in
  # AggregatorService::DEFAULT_SERVICES. Use it on demand, the same way
  # Pulsedive is used.
  #
  class HybridAnalysisService < BaseService
    BASE_URL = "https://www.hybrid-analysis.com/api/v2/"

    rate_limit :minute, requests: 5,   period: 1.minute
    rate_limit :hourly, requests: 200, period: 1.hour

    # Sandbox reports do not change after they finish, so the answer for an
    # indicator is stable. Cache hard: the minute limit is the real constraint.
    CACHE_TTL = 12.hours

    # Report verdicts, as the API spells them
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NO_SPECIFIC_THREAT = "no specific threat"
    WHITELISTED = "whitelisted"

    # A busy domain can match thousands of reports. We only score the page the
    # API gives us, and record the full count in the details.
    MAX_REPORTS_SCORED = 25

    # A search hit is not a conviction, and the two search terms do not carry
    # the same weight. A url search matches reports for that exact URL, so a
    # malicious report is about the thing we asked about. A domain search
    # matches every report whose sample contacted the domain, so shared
    # hosting, URL shorteners and CDNs collect malicious reports without being
    # phishing themselves. Domain answers are therefore capped lower, and a
    # domain needs most of its reports to agree before we call it phishing
    # rather than suspicious.
    URL_CONFIDENCE_CEILING = 0.9
    DOMAIN_CONFIDENCE_CEILING = 0.7
    DOMAIN_MALICIOUS_RATIO = 0.5

    # A malicious report is worth reporting even when the ratio and the threat
    # score are both low, so keep the answer above the aggregator's default
    # 0.3 confidence floor.
    MIN_MALICIOUS_CONFIDENCE = 0.35

    # Confidence for the verdicts that need no arithmetic
    SUSPICIOUS_CONFIDENCE = 0.5
    WHITELISTED_CONFIDENCE = 0.8
    NO_SPECIFIC_THREAT_CONFIDENCE = 0.6

    def check_domain(domain)
      lookup(term: :domain, value: normalize_domain(domain))
    end

    def check_url(url)
      lookup(term: :url, value: normalize_url(url))
    end

    private

    def lookup(term:, value:)
      log_info("Checking #{term}: #{value}")

      cached = read_cache(term, value)
      return cached if cached

      with_rate_limit do
        response = search(term, value)
        result = parse_search_response(response, term: term, value: value)
        write_cache(term, value, result)
        result
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    def search(term, value)
      response = post(authenticated_connection, "search/terms", term => value)
      response.is_a?(Hash) ? response : {}
    end

    def credentials
      Rails.application.credentials.hybrid_analysis || {}
    end

    def api_key
      credentials[:api_key]
    end

    def authenticated_connection
      raise AuthenticationError, "Hybrid Analysis API key not configured" unless api_key

      connection(
        base_url: BASE_URL,
        headers: { "api-key" => api_key },
        request_encoding: :url_encoded
      )
    end

    def parse_search_response(response, term:, value:)
      reports = Array(response["result"])
      return build_no_reports_result(term, value) if reports.empty?

      scored = reports.first(MAX_REPORTS_SCORED)
      counts = tally_verdicts(scored)
      threat_score = scored.filter_map { |report| report["threat_score"] }.max
      verdict, confidence = classify(counts, threat_score: threat_score, term: term)

      build_result(
        verdict: verdict,
        confidence: confidence,
        details: {
          term => value,
          search_term: term,
          reports_total: response["count"] || reports.size,
          reports_scored: scored.size,
          verdict_counts: counts,
          max_threat_score: threat_score,
          families: families(scored),
          reports: summarize(scored),
          source: "hybrid_analysis"
        }
      )
    end

    def build_no_reports_result(term, value)
      log_info("No Hybrid Analysis reports for #{term}: #{value}")

      build_result(
        verdict: "unknown",
        confidence: 0.0,
        details: {
          term => value,
          search_term: term,
          reports_total: 0,
          not_found: true,
          source: "hybrid_analysis"
        }
      )
    end

    def tally_verdicts(reports)
      reports.each_with_object(Hash.new(0)) do |report, counts|
        counts[report["verdict"].to_s.downcase.presence || "unknown"] += 1
      end
    end

    def classify(counts, threat_score:, term:)
      total = counts.values.sum
      malicious = counts[MALICIOUS]

      if malicious.positive?
        ratio = malicious.to_f / total
        confidence = malicious_confidence(ratio, threat_score, term)

        # A minority of malicious reports on a domain is a lead, not a verdict.
        return [ "suspicious", confidence ] if term == :domain && ratio < DOMAIN_MALICIOUS_RATIO

        return [ "phishing", confidence ]
      end

      return [ "suspicious", SUSPICIOUS_CONFIDENCE ] if counts[SUSPICIOUS].positive?
      return [ "clean", WHITELISTED_CONFIDENCE ] if counts[WHITELISTED].positive?
      return [ "clean", NO_SPECIFIC_THREAT_CONFIDENCE ] if counts[NO_SPECIFIC_THREAT].positive?

      # Reports exist but none of them reached a verdict.
      [ "unknown", 0.0 ]
    end

    # How much of the evidence points one way, refined by how bad the worst
    # report was. threat_score runs 0 to 100.
    def malicious_confidence(ratio, threat_score, term)
      ceiling = term == :domain ? DOMAIN_CONFIDENCE_CEILING : URL_CONFIDENCE_CEILING
      score = threat_score.to_f.clamp(0.0, 100.0) / 100.0
      raw = ((0.6 * ratio) + (0.4 * score)) * ceiling

      raw.clamp(MIN_MALICIOUS_CONFIDENCE, ceiling).round(2)
    end

    def families(reports)
      reports.filter_map { |report| report["vx_family"].presence }.uniq
    end

    def summarize(reports)
      reports.map do |report|
        {
          sha256: report["sha256"],
          submit_name: report["submit_name"],
          verdict: report["verdict"],
          threat_score: report["threat_score"],
          threat_level: report["threat_level"],
          av_detect: report["av_detect"],
          vx_family: report["vx_family"],
          analysis_start_time: report["analysis_start_time"],
          environment_description: report["environment_description"]
        }
      end
    end

    def cache_key(term, value)
      "hybrid_analysis:#{term}:#{Digest::SHA256.hexdigest(value.to_s)}"
    end

    def read_cache(term, value)
      Rails.cache.read(cache_key(term, value))
    end

    def write_cache(term, value, result)
      Rails.cache.write(cache_key(term, value), result, expires_in: CACHE_TTL)
    end
  end
end
