# frozen_string_literal: true

module Phish
  # urlDNA.io API
  # https://docs.urldna.io/api-reference/introduction
  #
  # Two ways to ask urlDNA about a URL:
  #
  #   1. Fast Check (POST /v1/fast-check) answers from existing threat
  #      intelligence and returns immediately. This is what #check_url uses.
  #   2. Create Scan (POST /v1/scan) launches a full browser scan. It returns a
  #      PENDING record, and the result has to be collected later with
  #      #get_scan_result. #submit_scan exposes this for callers that want the
  #      full page analysis: certificates, redirect chains, technologies.
  #
  # Quotas (https://docs.urldna.io/api-reference/api-usage):
  #   Free:    100 requests/day
  #   Premium: 5000 requests/day
  #
  # The quota is shared across Create Scan, Get Scan, Search, Query Scans,
  # Brand Scans and Fast Check, and it resets every 24 hours. There are no
  # documented per-minute limits.
  #
  # The daily allowance is small, so results are cached and this service is not
  # in AggregatorService::DEFAULT_SERVICES. It is registered in ServiceFactory
  # and is meant to be called on demand, the same way Pulsedive is.
  #
  class UrldnaService < BaseService
    BASE_URL = "https://api.urldna.io/v1/"

    # Free tier is 100/day. Stopping at 90 leaves room for manual lookups and
    # for the Get Scan calls that collect full scans submitted earlier.
    rate_limit :daily, requests: 90, period: 1.day

    # Cache TTL. A day's allowance disappears quickly, and a verdict on a URL
    # rarely changes within a few hours.
    CACHE_TTL = 12.hours

    # Fast Check statuses, mapped to our verdicts.
    STATUS_VERDICTS = {
      "MALICIOUS" => "phishing",
      "SAFE" => "clean",
      "UNRATED" => "unknown"
    }.freeze

    # A definite verdict with no usable score still has to mean something.
    DEFAULT_MALICIOUS_CONFIDENCE = 0.80
    DEFAULT_SAFE_CONFIDENCE = 0.80

    # AggregatorService drops any result below its minimum confidence before
    # the weighted vote. A MALICIOUS answer is a positive statement, so it
    # keeps a floor rather than being discarded when the engine is unsure.
    MIN_MALICIOUS_CONFIDENCE = 0.50

    # Full scan statuses. Only DONE carries a classification.
    SCAN_STATUS_PENDING = %w[PENDING RUNNING].freeze
    SCAN_STATUS_FAILED = %w[ERROR PAGE_NOT_AVAILABLE].freeze

    def check_domain(domain)
      normalized = normalize_domain(domain)
      check_url("https://#{normalized}")
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

      cached = read_cached_result(normalized)
      return cached if cached

      with_rate_limit(action: :fast_check) do
        conn = authenticated_connection
        response = ensure_hash(post(conn, "fast-check", { url: normalized }))
        result = parse_fast_check(response, normalized)
        write_cached_result(normalized, result)
        result
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # Launch a full browser scan. Returns a pending result: the scan runs
    # asynchronously and #get_scan_result collects it once it is DONE.
    #
    # @param url [String] The URL to scan
    # @param private_scan [Boolean] Keep the result off the public feed
    # @return [Hash] A pending result carrying the scan id
    def submit_scan(url, private_scan: true)
      normalized = normalize_url(url)
      log_info("Submitting URL for scan: #{normalized}")

      with_rate_limit(action: :scan) do
        conn = authenticated_connection
        response = ensure_hash(post(conn, "scan", {
          submitted_url: normalized,
          private_scan: private_scan
        }))

        build_result(
          verdict: "pending",
          confidence: 0.0,
          details: {
            url: normalized,
            scan_id: response["id"],
            scan_status: response["status"],
            submitted_date: response["submitted_date"],
            source: "urldna"
          }
        )
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    # Collect the result of a scan submitted with #submit_scan.
    #
    # @param scan_id [String] The id returned by #submit_scan
    # @return [Hash] The verdict, or a pending result if the scan is still running
    def get_scan_result(scan_id)
      log_info("Fetching scan result: #{scan_id}")

      with_rate_limit(action: :retrieve) do
        conn = authenticated_connection
        response = ensure_hash(get(conn, "scan/#{scan_id}"))
        parse_scan_result(response, scan_id)
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: e.retry_after)
    end

    private

    def credentials
      Rails.application.credentials.urldna || {}
    end

    def api_key
      credentials[:api_key]
    end

    def authenticated_connection
      raise AuthenticationError, "urlDNA API key not configured" if api_key.blank?

      connection(
        base_url: BASE_URL,
        headers: { "Authorization" => "Bearer #{api_key}" }
      )
    end

    def parse_fast_check(response, url)
      status = response["status"].to_s.upcase
      score = parse_score(response["malicious_score"])
      verdict = STATUS_VERDICTS[status] || "unknown"

      build_result(
        verdict: verdict,
        confidence: confidence_for(status, score),
        details: {
          url: url,
          status: status,
          malicious_score: score,
          scan_id: response["scan_id"],
          check: "fast_check",
          source: "urldna"
        }
      )
    end

    def parse_scan_result(response, scan_id)
      status = response["status"].to_s.upcase
      url = response["submitted_url"] || response["target_url"]

      return build_scan_pending_result(response, scan_id, url, status) if SCAN_STATUS_PENDING.include?(status)
      return build_scan_failed_result(response, scan_id, url, status) if SCAN_STATUS_FAILED.include?(status)

      # A DONE scan carries the AI engine's classification.
      verdict_name = response.dig("classification", "verdict").to_s.upcase

      build_result(
        verdict: STATUS_VERDICTS[verdict_name] || "unknown",
        confidence: confidence_for(verdict_name, nil),
        details: {
          url: url,
          scan_id: response["id"] || scan_id,
          scan_status: status,
          classification: verdict_name,
          domain: response["domain"],
          nsfw: response["nsfw"],
          check: "scan",
          source: "urldna"
        }
      )
    end

    def build_scan_pending_result(response, scan_id, url, status)
      build_result(
        verdict: "pending",
        confidence: 0.0,
        details: {
          url: url,
          scan_id: response["id"] || scan_id,
          scan_status: status,
          check: "scan",
          source: "urldna"
        }
      )
    end

    def build_scan_failed_result(response, scan_id, url, status)
      log_info("Scan #{scan_id} finished with status #{status}")

      build_result(
        verdict: "unknown",
        confidence: 0.0,
        details: {
          url: url,
          scan_id: response["id"] || scan_id,
          scan_status: status,
          check: "scan",
          source: "urldna"
        }
      )
    end

    # urlDNA reports a categorical status and a 0-1 malicious score. The status
    # decides the verdict; the score decides how much that verdict is worth, so
    # a score of 0.95 and one of 0.35 do not carry the same weight in the
    # aggregate. Full scans report no score, so they fall back to the defaults.
    def confidence_for(status, score)
      case status
      when "MALICIOUS"
        return DEFAULT_MALICIOUS_CONFIDENCE unless score

        [ score, MIN_MALICIOUS_CONFIDENCE ].max.round(2)
      when "SAFE"
        return DEFAULT_SAFE_CONFIDENCE unless score

        (1.0 - score).round(2)
      else
        0.0
      end
    end

    # Returns the score as a float in 0..1, or nil when it is missing or is not
    # a number. Booleans and strings from an unexpected payload must not turn
    # into a confidence of 0.0.
    def parse_score(value)
      return nil unless value.is_a?(Numeric)

      value.to_f.clamp(0.0, 1.0)
    end

    def result_cache_key(url)
      "urldna:fast_check:#{Digest::SHA256.hexdigest(url.to_s)}"
    end

    def read_cached_result(url)
      Rails.cache.read(result_cache_key(url))
    end

    def write_cached_result(url, result)
      Rails.cache.write(result_cache_key(url), result, expires_in: CACHE_TTL)
    end

    def ensure_hash(response)
      return response if response.is_a?(Hash)

      begin
        parsed = JSON.parse(response.to_s)
        parsed.is_a?(Hash) ? parsed : {}
      rescue JSON::ParserError
        log_error("Failed to parse response as JSON", StandardError.new(response.to_s.truncate(200)))
        {}
      end
    end
  end
end
