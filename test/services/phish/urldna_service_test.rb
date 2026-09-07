# frozen_string_literal: true

require "test_helper"

class Phish::UrldnaServiceTest < ActiveSupport::TestCase
  # Credentials are not set in test, so a subclass supplies a key.
  class TestableUrldnaService < Phish::UrldnaService
    private

    def credentials
      { api_key: "test_api_key" }
    end
  end

  setup do
    @service = TestableUrldnaService.new
  end

  test "service_name returns urldna for the real service" do
    assert_equal "urldna", Phish::UrldnaService.new.service_name
  end

  test "check_url returns phishing verdict for malicious status" do
    stub_fast_check(status: "MALICIOUS", malicious_score: 0.93, scan_id: "scan_123")

    result = @service.check_url("https://evil.example/login")

    assert_equal "phishing", result[:verdict]
    assert_equal 0.93, result[:confidence]
    assert_equal "urldna", result[:details][:source]
    assert_equal "MALICIOUS", result[:details][:status]
    assert_equal "scan_123", result[:details][:scan_id]
    assert_equal "fast_check", result[:details][:check]
  end

  test "check_url floors malicious confidence so the verdict survives aggregation" do
    # A confidence below the aggregator's minimum is dropped from the weighted
    # vote entirely, so a definite MALICIOUS answer keeps a floor.
    stub_fast_check(status: "MALICIOUS", malicious_score: 0.11)

    result = @service.check_url("https://evil.example")

    assert_equal "phishing", result[:verdict]
    assert_equal Phish::UrldnaService::MIN_MALICIOUS_CONFIDENCE, result[:confidence]
  end

  test "check_url returns clean verdict for safe status" do
    stub_fast_check(status: "SAFE", malicious_score: 0.05)

    result = @service.check_url("https://good.example")

    assert_equal "clean", result[:verdict]
    assert_equal 0.95, result[:confidence]
  end

  test "check_url returns unknown verdict for unrated status" do
    stub_fast_check(status: "UNRATED", malicious_score: 0.0)

    result = @service.check_url("https://nobody.example")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
  end

  test "check_url falls back to default confidence when the score is missing" do
    stub_fast_check(status: "MALICIOUS")

    result = @service.check_url("https://evil.example")

    assert_equal "phishing", result[:verdict]
    assert_equal Phish::UrldnaService::DEFAULT_MALICIOUS_CONFIDENCE, result[:confidence]
    assert_nil result[:details][:malicious_score]
  end

  test "check_url ignores a non numeric score rather than treating it as zero" do
    stub_fast_check(status: "SAFE", malicious_score: "high")

    result = @service.check_url("https://good.example")

    assert_equal "clean", result[:verdict]
    assert_equal Phish::UrldnaService::DEFAULT_SAFE_CONFIDENCE, result[:confidence]
  end

  test "check_url returns unknown for an unrecognised status" do
    stub_fast_check(status: "SOMETHING_NEW", malicious_score: 0.9)

    result = @service.check_url("https://weird.example")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
  end

  test "check_url sends the bearer token and the normalized url" do
    stub_fast_check(status: "SAFE", malicious_score: 0.0)

    @service.check_url("HTTPS://GOOD.EXAMPLE/Path")

    assert_requested(:post, "https://api.urldna.io/v1/fast-check") do |request|
      request.headers["Authorization"] == "Bearer test_api_key" &&
        JSON.parse(request.body)["url"] == "https://good.example/Path"
    end
  end

  test "check_domain checks the domain as an https url" do
    stub_fast_check(status: "MALICIOUS", malicious_score: 0.8)

    result = @service.check_domain("https://EVIL.EXAMPLE/login?a=1")

    assert_equal "phishing", result[:verdict]
    assert_requested(:post, "https://api.urldna.io/v1/fast-check") do |request|
      JSON.parse(request.body)["url"] == "https://evil.example"
    end
  end

  test "check_url caches results to protect the daily quota" do
    with_memory_cache do
      stub_fast_check(status: "MALICIOUS", malicious_score: 0.9)

      first = @service.check_url("https://evil.example")
      second = @service.check_url("https://evil.example")

      assert_equal first[:verdict], second[:verdict]
      assert_equal first[:confidence], second[:confidence]
      assert_requested :post, "https://api.urldna.io/v1/fast-check", times: 1
    end
  end

  test "check_url raises AuthenticationError when no api key is configured" do
    service = Phish::UrldnaService.new

    assert_raises(Phish::BaseService::AuthenticationError) do
      service.check_url("https://good.example")
    end
  end

  test "check_url raises RateLimitError when urlDNA returns 429" do
    stub_request(:post, "https://api.urldna.io/v1/fast-check")
      .to_return(status: 429, headers: { "Retry-After" => "120" })

    error = assert_raises(Phish::BaseService::RateLimitError) do
      @service.check_url("https://evil.example")
    end

    assert_equal 120, error.retry_after
  end

  test "submit_scan returns a pending result carrying the scan id" do
    stub_request(:post, "https://api.urldna.io/v1/scan")
      .to_return(
        status: 200,
        body: {
          id: "scan_abc",
          submitted_url: "https://evil.example",
          status: "PENDING",
          submitted_date: "2026-09-07T00:00:00Z"
        }.to_json,
        headers: { "Content-Type" => "application/json" }
      )

    result = @service.submit_scan("https://evil.example")

    assert_equal "pending", result[:verdict]
    assert_equal 0.0, result[:confidence]
    assert_equal "scan_abc", result[:details][:scan_id]
    assert_equal "PENDING", result[:details][:scan_status]

    assert_requested(:post, "https://api.urldna.io/v1/scan") do |request|
      body = JSON.parse(request.body)
      body["submitted_url"] == "https://evil.example" && body["private_scan"] == true
    end
  end

  test "get_scan_result returns phishing for a done malicious scan" do
    stub_get_scan("scan_abc", status: "DONE", classification: { verdict: "MALICIOUS" })

    result = @service.get_scan_result("scan_abc")

    assert_equal "phishing", result[:verdict]
    assert_equal Phish::UrldnaService::DEFAULT_MALICIOUS_CONFIDENCE, result[:confidence]
    assert_equal "MALICIOUS", result[:details][:classification]
    assert_equal "scan", result[:details][:check]
  end

  test "get_scan_result returns clean for a done safe scan" do
    stub_get_scan("scan_abc", status: "DONE", classification: { verdict: "SAFE" })

    result = @service.get_scan_result("scan_abc")

    assert_equal "clean", result[:verdict]
    assert_equal Phish::UrldnaService::DEFAULT_SAFE_CONFIDENCE, result[:confidence]
  end

  test "get_scan_result stays pending while the scan is running" do
    stub_get_scan("scan_abc", status: "RUNNING")

    result = @service.get_scan_result("scan_abc")

    assert_equal "pending", result[:verdict]
    assert_equal "RUNNING", result[:details][:scan_status]
  end

  test "get_scan_result returns unknown when the page could not be loaded" do
    stub_get_scan("scan_abc", status: "PAGE_NOT_AVAILABLE")

    result = @service.get_scan_result("scan_abc")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
    assert_equal "PAGE_NOT_AVAILABLE", result[:details][:scan_status]
  end

  test "ServiceFactory builds the service" do
    assert Phish::ServiceFactory.registered?(:urldna)
    assert_instance_of Phish::UrldnaService, Phish::ServiceFactory.build(:urldna)
  end

  private

  def stub_fast_check(status:, malicious_score: :none, scan_id: nil)
    body = { url: "https://example.com", status: status }
    body[:malicious_score] = malicious_score unless malicious_score == :none
    body[:scan_id] = scan_id if scan_id

    stub_request(:post, "https://api.urldna.io/v1/fast-check")
      .to_return(
        status: 200,
        body: body.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  def stub_get_scan(scan_id, status:, classification: nil)
    body = {
      id: scan_id,
      submitted_url: "https://evil.example",
      status: status
    }
    body[:classification] = classification if classification

    stub_request(:get, "https://api.urldna.io/v1/scan/#{scan_id}")
      .to_return(
        status: 200,
        body: body.to_json,
        headers: { "Content-Type" => "application/json" }
      )
  end

  # The test environment uses a null store, so caching needs a real one.
  def with_memory_cache
    original = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new
    yield
  ensure
    Rails.cache = original
  end
end
