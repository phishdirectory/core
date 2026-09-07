# frozen_string_literal: true

require "test_helper"

class Phish::HybridAnalysisServiceTest < ActiveSupport::TestCase
  # The real service reads the API key from credentials, which the test
  # environment does not carry.
  class TestableHybridAnalysisService < Phish::HybridAnalysisService
    private

    def credentials
      { api_key: "test_api_key" }
    end
  end

  # Credentials are absent in this environment, but do not depend on that.
  class UnconfiguredHybridAnalysisService < Phish::HybridAnalysisService
    private

    def credentials
      {}
    end
  end

  setup do
    @service = TestableHybridAnalysisService.new
  end

  test "service_name returns hybrid_analysis" do
    assert_equal "hybrid_analysis", Phish::HybridAnalysisService.new.service_name
  end

  test "the factory builds the service" do
    assert_instance_of Phish::HybridAnalysisService, Phish::ServiceFactory.build(:hybrid_analysis)
  end

  test "check_domain returns phishing when most reports are malicious" do
    stub_search("domain", "malicious.com", [
      report(verdict: "malicious", threat_score: 100, vx_family: "Phishing"),
      report(verdict: "malicious", threat_score: 80),
      report(verdict: "no specific threat", threat_score: 5)
    ])

    result = @service.check_domain("malicious.com")

    assert_equal "phishing", result[:verdict]
    # ratio 0.67, threat score 1.0, capped at the domain ceiling of 0.7
    assert_equal 0.56, result[:confidence]
    assert_equal "hybrid_analysis", result[:details][:source]
    assert_equal "malicious.com", result[:details][:domain]
    assert_equal 3, result[:details][:reports_scored]
    assert_equal 2, result[:details][:verdict_counts]["malicious"]
    assert_equal [ "Phishing" ], result[:details][:families]
  end

  test "check_domain returns suspicious when a minority of reports are malicious" do
    stub_search("domain", "shared-host.com", [
      report(verdict: "malicious", threat_score: 90),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "whitelisted", threat_score: 0)
    ])

    result = @service.check_domain("shared-host.com")

    assert_equal "suspicious", result[:verdict]
    assert result[:confidence] < Phish::HybridAnalysisService::DOMAIN_CONFIDENCE_CEILING
  end

  test "check_domain never answers above the domain ceiling" do
    stub_search("domain", "all-bad.com", [
      report(verdict: "malicious", threat_score: 100),
      report(verdict: "malicious", threat_score: 100)
    ])

    result = @service.check_domain("all-bad.com")

    assert_equal "phishing", result[:verdict]
    assert_equal Phish::HybridAnalysisService::DOMAIN_CONFIDENCE_CEILING, result[:confidence]
  end

  test "check_url returns phishing with a higher ceiling than a domain" do
    stub_search("url", "https://evil.com/login", [
      report(verdict: "malicious", threat_score: 100, vx_family: "Phishing")
    ])

    result = @service.check_url("https://evil.com/login")

    assert_equal "phishing", result[:verdict]
    assert_equal Phish::HybridAnalysisService::URL_CONFIDENCE_CEILING, result[:confidence]
    assert_equal "https://evil.com/login", result[:details][:url]
  end

  test "check_url returns suspicious for a lone malicious report only on domains" do
    stub_search("url", "https://mixed.com/page", [
      report(verdict: "malicious", threat_score: 10),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0)
    ])

    result = @service.check_url("https://mixed.com/page")

    # A url search matches the exact URL, so the minority rule does not apply.
    assert_equal "phishing", result[:verdict]
  end

  test "malicious verdicts stay above the aggregator confidence floor" do
    stub_search("url", "https://weak.com/page", [
      report(verdict: "malicious", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0),
      report(verdict: "no specific threat", threat_score: 0)
    ])

    result = @service.check_url("https://weak.com/page")

    assert_equal Phish::HybridAnalysisService::MIN_MALICIOUS_CONFIDENCE, result[:confidence]
  end

  test "check_domain returns suspicious when reports are suspicious" do
    stub_search("domain", "odd.com", [
      report(verdict: "suspicious", threat_score: 40)
    ])

    result = @service.check_domain("odd.com")

    assert_equal "suspicious", result[:verdict]
    assert_equal 0.5, result[:confidence]
  end

  test "check_domain returns clean for a whitelisted domain" do
    stub_search("domain", "google.com", [
      report(verdict: "whitelisted", threat_score: 0)
    ])

    result = @service.check_domain("google.com")

    assert_equal "clean", result[:verdict]
    assert_equal 0.8, result[:confidence]
  end

  test "check_domain returns clean when reports found no specific threat" do
    stub_search("domain", "boring.com", [
      report(verdict: "no specific threat", threat_score: 0)
    ])

    result = @service.check_domain("boring.com")

    assert_equal "clean", result[:verdict]
    assert_equal 0.6, result[:confidence]
  end

  test "check_domain returns unknown when reports carry no verdict" do
    stub_search("domain", "pending.com", [
      report(verdict: nil, threat_score: nil)
    ])

    result = @service.check_domain("pending.com")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
  end

  test "check_domain returns unknown when nothing matches" do
    stub_search("domain", "unheard-of.com", [])

    result = @service.check_domain("unheard-of.com")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
    assert result[:details][:not_found]
    assert_equal 0, result[:details][:reports_total]
  end

  test "check_domain scores at most MAX_REPORTS_SCORED reports" do
    reports = Array.new(40) { report(verdict: "malicious", threat_score: 100) }
    stub_search("domain", "busy.com", reports, count: 4_000)

    result = @service.check_domain("busy.com")

    assert_equal Phish::HybridAnalysisService::MAX_REPORTS_SCORED, result[:details][:reports_scored]
    assert_equal 4_000, result[:details][:reports_total]
    assert_equal Phish::HybridAnalysisService::MAX_REPORTS_SCORED, result[:details][:reports].size
  end

  test "check_domain normalizes the domain before searching" do
    stub_search("domain", "example.com", [ report(verdict: "whitelisted") ])

    result = @service.check_domain("https://EXAMPLE.COM/path?query=1")

    assert_equal "clean", result[:verdict]
    assert_requested :post, search_url, body: { "domain" => "example.com" }, times: 1
  end

  test "the request is form encoded and carries the api key" do
    stub_search("domain", "example.com", [ report(verdict: "whitelisted") ])

    @service.check_domain("example.com")

    assert_requested :post, search_url, times: 1 do |request|
      request.headers["Api-Key"] == "test_api_key" &&
        request.headers["Content-Type"].start_with?("application/x-www-form-urlencoded") &&
        request.body == "domain=example.com"
    end
  end

  test "repeated lookups are served from the cache" do
    original_cache = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new

    stub_search("domain", "cached.com", [ report(verdict: "malicious", threat_score: 100) ])

    first = @service.check_domain("cached.com")
    second = @service.check_domain("cached.com")

    assert_equal "phishing", first[:verdict]
    assert_equal first[:details][:reports], second[:details][:reports]
    assert_requested :post, search_url, times: 1
  ensure
    Rails.cache = original_cache
  end

  test "a missing api key raises an authentication error" do
    assert_raises Phish::BaseService::AuthenticationError do
      UnconfiguredHybridAnalysisService.new.check_domain("example.com")
    end
  end

  test "a 429 response raises a rate limit error carrying retry_after" do
    stub_request(:post, search_url).to_return(
      status: 429,
      body: { message: "Exceeded maximum API requests per minute(5)" }.to_json,
      headers: { "Content-Type" => "application/json", "Retry-After" => "30" }
    )

    error = assert_raises Phish::BaseService::RateLimitError do
      @service.check_domain("throttled.com")
    end

    assert_equal 30, error.retry_after
  end

  test "a 403 response raises an authentication error" do
    stub_request(:post, search_url).to_return(
      status: 403,
      body: { message: "Forbidden" }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    assert_raises Phish::BaseService::AuthenticationError do
      @service.check_domain("forbidden.com")
    end
  end

  test "exhausting the local rate limit raises a rate limit error" do
    original_cache = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new

    stub_request(:post, search_url).to_return(
      status: 200,
      body: { count: 0, result: [] }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    # The minute limit is 5 requests, and each domain is a distinct cache key.
    5.times { |i| @service.check_domain("limit-#{i}.com") }

    assert_raises Phish::BaseService::RateLimitError do
      @service.check_domain("limit-6.com")
    end
  ensure
    Rails.cache = original_cache
  end

  private

  def search_url
    "https://www.hybrid-analysis.com/api/v2/search/terms"
  end

  def report(verdict: "malicious", threat_score: 100, vx_family: nil)
    {
      "sha256" => SecureRandom.hex(32),
      "submit_name" => "sample.exe",
      "verdict" => verdict,
      "threat_score" => threat_score,
      "threat_level" => 2,
      "av_detect" => "50",
      "vx_family" => vx_family,
      "analysis_start_time" => "2026-01-01T00:00:00+00:00",
      "environment_description" => "Windows 10 64 bit"
    }
  end

  def stub_search(term, value, reports, count: nil)
    stub_request(:post, search_url)
      .with(body: { term => value })
      .to_return(
        status: 200,
        body: { count: count || reports.size, search_terms: [ { id: term, value: value } ], result: reports }.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end
end
