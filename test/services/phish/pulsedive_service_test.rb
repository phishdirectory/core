# frozen_string_literal: true

require "test_helper"

class Phish::PulsediveServiceTest < ActiveSupport::TestCase
  # Create a testable subclass that provides credentials
  class TestablePulsediveService < Phish::PulsediveService
    private

    def credentials
      { api_key: "test_api_key" }
    end
  end

  setup do
    @service = TestablePulsediveService.new
  end

  test "service_name returns testable_pulsedive for test subclass" do
    # The test subclass has a different name; the actual service returns "pulsedive"
    assert_equal "testable_pulsedive", @service.service_name
    assert_equal "pulsedive", Phish::PulsediveService.new.service_name
  end

  test "check_domain returns phishing verdict for critical risk" do
    stub_pulsedive_response("malicious.com", {
      iid: 12345,
      type: "domain",
      indicator: "malicious.com",
      risk: "critical",
      stamp_added: "2024-01-01 00:00:00",
      threats: [{ "name" => "Phishing" }]
    })

    result = @service.check_domain("malicious.com")

    assert_equal "phishing", result[:verdict]
    assert_equal 0.95, result[:confidence]
    assert_equal "pulsedive", result[:details][:source]
    assert_equal 12345, result[:details][:iid]
  end

  test "check_domain returns phishing verdict for high risk" do
    stub_pulsedive_response("suspicious.com", {
      iid: 12346,
      type: "domain",
      indicator: "suspicious.com",
      risk: "high"
    })

    result = @service.check_domain("suspicious.com")

    assert_equal "phishing", result[:verdict]
    assert_equal 0.85, result[:confidence]
  end

  test "check_domain returns suspicious verdict for medium risk" do
    stub_pulsedive_response("risky.com", {
      iid: 12347,
      type: "domain",
      indicator: "risky.com",
      risk: "medium"
    })

    result = @service.check_domain("risky.com")

    assert_equal "suspicious", result[:verdict]
    assert_equal 0.65, result[:confidence]
  end

  test "check_domain returns clean verdict for low risk" do
    stub_pulsedive_response("normal.com", {
      iid: 12348,
      type: "domain",
      indicator: "normal.com",
      risk: "low"
    })

    result = @service.check_domain("normal.com")

    assert_equal "clean", result[:verdict]
    assert_equal 0.70, result[:confidence]
  end

  test "check_domain returns clean verdict for no risk" do
    stub_pulsedive_response("safe.com", {
      iid: 12349,
      type: "domain",
      indicator: "safe.com",
      risk: "none"
    })

    result = @service.check_domain("safe.com")

    assert_equal "clean", result[:verdict]
    assert_equal 0.80, result[:confidence]
  end

  test "check_domain returns unknown verdict for unknown risk" do
    stub_pulsedive_response("unknown.com", {
      iid: 12350,
      type: "domain",
      indicator: "unknown.com",
      risk: "unknown"
    })

    result = @service.check_domain("unknown.com")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
  end

  test "check_domain handles not found error" do
    stub_pulsedive_response("notfound.com", { error: "Indicator not found." })

    result = @service.check_domain("notfound.com")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
    assert_match(/not found/i, result[:details][:error])
  end

  test "check_domain uses cache on repeated calls" do
    # Use memory store to test caching (test env uses null_store by default)
    original_cache = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new

    stub_pulsedive_response("cached.com", {
      iid: 12351,
      type: "domain",
      indicator: "cached.com",
      risk: "critical"
    })

    # First call - should hit API
    result1 = @service.check_domain("cached.com")
    assert_equal "phishing", result1[:verdict]

    # Second call - should return cached result
    # The stub is still present but we verify request was only made once
    result2 = @service.check_domain("cached.com")
    assert_equal "phishing", result2[:verdict]
    assert_equal result1[:details][:iid], result2[:details][:iid]

    # Verify only one request was made (proves caching worked)
    assert_requested :get, /pulsedive\.com\/api\/info\.php/, times: 1
  ensure
    Rails.cache = original_cache
  end

  test "check_domain normalizes domain input" do
    stub_pulsedive_response("example.com", {
      iid: 12352,
      type: "domain",
      indicator: "example.com",
      risk: "none"
    })

    result = @service.check_domain("https://EXAMPLE.COM/path?query=1")

    assert_equal "clean", result[:verdict]
    assert_equal "pulsedive", result[:details][:source]
  end

  test "check_url returns result" do
    stub_pulsedive_response("https://example.com/path", {
      iid: 12353,
      type: "url",
      indicator: "https://example.com/path",
      risk: "high"
    })

    result = @service.check_url("https://example.com/path")

    assert_equal "phishing", result[:verdict]
    assert_equal 0.85, result[:confidence]
  end

  test "check_domain includes threat and feed information" do
    stub_pulsedive_response("threatfeed.com", {
      iid: 12354,
      type: "domain",
      indicator: "threatfeed.com",
      risk: "high",
      threats: [{ "name" => "Phishing" }, { "name" => "Malware" }],
      feeds: [{ "name" => "OpenPhish" }],
      riskfactors: [{ "description" => "Known phishing domain" }]
    })

    result = @service.check_domain("threatfeed.com")

    assert_equal 2, result[:details][:threats].size
    assert_equal 1, result[:details][:feeds].size
    assert_equal 1, result[:details][:riskfactors].size
  end

  private

  def stub_pulsedive_response(indicator, response)
    # Handle both domain and URL formats
    normalized = if indicator.start_with?("http")
      indicator
    else
      indicator.sub(%r{\Ahttps?://}, "").split("/").first.split(":").first.downcase
    end

    stub_request(:get, /pulsedive\.com\/api\/info\.php/)
      .with(query: hash_including("indicator" => normalized))
      .to_return(
        status: 200,
        body: response.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end
end
