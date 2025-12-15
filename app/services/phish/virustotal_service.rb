# frozen_string_literal: true

module Phish
  # VirusTotal API v3
  # https://developers.virustotal.com/reference
  class VirustotalService < BaseService
    BASE_URL = "https://www.virustotal.com/api/v3/"

    # Threshold for considering a domain/URL as phishing
    MALICIOUS_THRESHOLD = 3

    def check_domain(domain)
      normalized = normalize_domain(domain)
      log_info("Checking domain: #{normalized}")

      conn = authenticated_connection
      response = get(conn, "domains/#{normalized}")

      parse_domain_response(response, normalized)
    end

    def check_url(url)
      normalized = normalize_url(url)
      log_info("Checking URL: #{normalized}")

      # URL needs to be base64 encoded (URL-safe, no padding)
      url_id = Base64.urlsafe_encode64(normalized, padding: false)

      conn = authenticated_connection
      response = get(conn, "urls/#{url_id}")

      parse_url_response(response, normalized)
    rescue Faraday::ResourceNotFound
      # URL not in VT database, submit for analysis
      submit_url(normalized)
    end

    def submit_url(url)
      normalized = normalize_url(url)
      log_info("Submitting URL for analysis: #{normalized}")

      conn = authenticated_connection
      response = post(conn, "urls", { url: normalized })

      build_result(
        verdict: "pending",
        confidence: 0.0,
        details: {
          analysis_id: response.dig("data", "id"),
          source: "virustotal",
          status: "submitted_for_analysis"
        }
      )
    end

    private

    def credentials
      Rails.application.credentials.virustotal || {}
    end

    def authenticated_connection
      api_key = credentials[:api_key]
      raise AuthenticationError, "VirusTotal API key not configured" unless api_key

      connection(
        base_url: BASE_URL,
        headers: { "x-apikey" => api_key }
      )
    end

    def parse_domain_response(response, domain)
      response = ensure_hash_response(response)
      stats = response.dig("data", "attributes", "last_analysis_stats") || {}
      malicious = stats["malicious"].to_i + stats["suspicious"].to_i
      total = stats.values.sum

      verdict = malicious >= MALICIOUS_THRESHOLD ? "phishing" : "clean"
      confidence = total.positive? ? (1.0 - (malicious.to_f / total)).clamp(0.0, 1.0) : 0.5

      # Invert confidence for phishing verdicts (higher malicious = higher confidence)
      confidence = 1.0 - confidence if verdict == "phishing"

      build_result(
        verdict: verdict,
        confidence: confidence.round(2),
        details: {
          domain: domain,
          stats: stats,
          malicious_count: malicious,
          total_engines: total,
          reputation: response.dig("data", "attributes", "reputation"),
          source: "virustotal"
        }
      )
    end

    def parse_url_response(response, url)
      response = ensure_hash_response(response)
      stats = response.dig("data", "attributes", "last_analysis_stats") || {}
      malicious = stats["malicious"].to_i + stats["suspicious"].to_i
      total = stats.values.sum

      verdict = malicious >= MALICIOUS_THRESHOLD ? "phishing" : "clean"
      confidence = total.positive? ? (malicious.to_f / total) : 0.5

      build_result(
        verdict: verdict,
        confidence: confidence.round(2),
        details: {
          url: url,
          stats: stats,
          malicious_count: malicious,
          total_engines: total,
          source: "virustotal"
        }
      )
    end

    def ensure_hash_response(response)
      return response if response.is_a?(Hash)

      begin
        JSON.parse(response.to_s)
      rescue JSON::ParserError
        log_error("Failed to parse response as JSON", StandardError.new(response.to_s.truncate(200)))
        {}
      end
    end
  end
end
