# frozen_string_literal: true

require "test_helper"

class Phish::AggregatorServiceTest < ActiveSupport::TestCase
  # Stands in for a detection service. The aggregator only ever calls
  # #service_name, #check_domain and #check_url on its collaborators.
  class FakeService
    attr_reader :service_name

    def initialize(name, result: nil, error: nil)
      @service_name = name
      @result = result
      @error = error
    end

    def check_domain(_value)
      raise @error if @error

      @result
    end
    alias_method :check_url, :check_domain
  end

  def verdict_from(name, verdict, confidence)
    FakeService.new(
      name,
      result: { service: name, verdict: verdict, confidence: confidence, details: {} }
    )
  end

  def failing(name, error)
    FakeService.new(name, error: error)
  end

  # The constructor resolves symbols through ServiceFactory. Injecting the
  # collaborators directly keeps these tests about the scoring algorithm.
  #
  # The scoring config is pinned too, so these assertions describe the
  # algorithm rather than whatever per-service weights the credentials
  # currently carry.
  SCORING = { min_confidence: 0.3, default_weight: 1.0, weights: {} }.freeze

  def aggregator(*fakes)
    service = Phish::AggregatorService.new(services: [])
    service.instance_variable_set(:@services, fakes)
    service.instance_variable_set(:@scoring_config, SCORING)
    service
  end

  # ===========================================
  # Scoring
  # ===========================================

  test "an authoritative source detecting phishing overrides the weighted vote" do
    result = aggregator(
      verdict_from("fish_fish", "phishing", 0.99),
      verdict_from("virustotal", "clean", 0.9),
      verdict_from("walshy", "clean", 0.9)
    ).check_domain("bad.com")

    assert_equal "phishing", result[:verdict]
    assert_equal "fish_fish", result[:details][:authoritative_source]
    assert_equal "Authoritative source detection", result[:details][:reason]
  end

  test "an authoritative source below the confidence bar does not override" do
    result = aggregator(
      verdict_from("sinking_yachts", "phishing", 0.5),
      verdict_from("virustotal", "clean", 0.95),
      verdict_from("walshy", "clean", 0.95)
    ).check_domain("good.com")

    assert_equal "clean", result[:verdict]
    assert_nil result[:details][:authoritative_source]
  end

  test "agreeing services produce a phishing verdict" do
    result = aggregator(
      verdict_from("virustotal", "phishing", 0.9),
      verdict_from("walshy", "phishing", 0.8)
    ).check_domain("bad.com")

    assert_equal "phishing", result[:verdict]
    assert result[:confidence] >= 0.3
  end

  test "agreeing services produce a clean verdict" do
    result = aggregator(
      verdict_from("virustotal", "clean", 0.9),
      verdict_from("walshy", "clean", 0.8)
    ).check_domain("good.com")

    assert_equal "clean", result[:verdict]
  end

  test "disagreeing services produce a suspicious verdict" do
    result = aggregator(
      verdict_from("virustotal", "phishing", 0.8),
      verdict_from("walshy", "clean", 0.8)
    ).check_domain("unclear.com")

    assert_equal "suspicious", result[:verdict]
  end

  test "results below the confidence threshold do not decide the verdict" do
    result = aggregator(
      verdict_from("virustotal", "phishing", 0.1),
      verdict_from("walshy", "clean", 0.1)
    ).check_domain("noisy.com")

    assert_equal "unknown", result[:verdict]
    assert_match(/confidence threshold/, result[:details][:reason])
  end

  # ===========================================
  # Failure isolation
  #
  # Response parsing runs outside BaseService#with_error_handling, so a vendor
  # returning unexpected JSON raises NoMethodError rather than ServiceError.
  # That must not cancel the other services.
  # ===========================================

  test "a service raising an unexpected error does not stop the others" do
    result = aggregator(
      failing("virustotal", NoMethodError.new("undefined method 'dig' for nil")),
      verdict_from("walshy", "phishing", 0.9),
      verdict_from("google_safe_browsing", "phishing", 0.9)
    ).check_domain("bad.com")

    assert_equal "phishing", result[:verdict],
                 "the two healthy services should still decide the verdict"
    assert_equal 2, result[:details][:services_checked]
    assert_equal 1, result[:details][:failed_services].size
    assert_equal "virustotal", result[:details][:failed_services].first[:service]
    assert_equal "NoMethodError", result[:details][:failed_services].first[:error]
  end

  test "a service raising a ServiceError does not stop the others" do
    result = aggregator(
      failing("virustotal", Phish::BaseService::ServiceError.new("upstream 502")),
      verdict_from("walshy", "clean", 0.9)
    ).check_domain("good.com")

    assert_equal "clean", result[:verdict]
    assert_equal 1, result[:details][:failed_services].size
  end

  test "every service failing reports unknown and flags the total failure" do
    result = aggregator(
      failing("virustotal", Phish::BaseService::ServiceError.new("upstream 502")),
      failing("walshy", NoMethodError.new("boom"))
    ).check_domain("nobody-knows.com")

    assert_equal "unknown", result[:verdict]
    assert result[:details][:all_services_failed],
           "callers must be able to tell an outage from a genuine no-data result"
    assert_match(/2 service\(s\) failed/, result[:details][:reason])
  end

  test "no services at all reports unknown without flagging a failure" do
    result = aggregator.check_domain("nothing.com")

    assert_equal "unknown", result[:verdict]
    assert_nil result[:details][:all_services_failed]
    assert_equal "No services returned results", result[:details][:reason]
  end

  test "a rate limited service is recorded rather than treated as a failure" do
    result = aggregator(
      failing("virustotal", Phish::BaseService::RateLimitError.new("slow down", retry_after: 30)),
      verdict_from("walshy", "clean", 0.9)
    ).check_domain("good.com")

    assert_equal "clean", result[:verdict]
    assert_nil result[:details][:failed_services]
    assert_equal "virustotal", result[:details][:rate_limited_services].first[:service]
    assert_equal 30, result[:details][:rate_limited_services].first[:retry_after]
  end

  # ===========================================
  # Protection
  # ===========================================

  test "a protected domain short circuits before any service runs" do
    domain = "protected-#{SecureRandom.hex(4)}.com"
    Phish::Protection.create!(
      protectable_type: "Phish::Domain",
      protectable_value: domain,
      protected_by: create_test_user
    )

    result = aggregator(
      failing("virustotal", NoMethodError.new("should never be called"))
    ).check_domain(domain)

    assert_equal "protected", result[:verdict]
    assert_equal 1.0, result[:confidence]
  end

  # ===========================================
  # URL path
  # ===========================================

  test "check_url isolates failures the same way check_domain does" do
    result = aggregator(
      failing("virustotal", NoMethodError.new("boom")),
      verdict_from("walshy", "phishing", 0.9),
      verdict_from("google_safe_browsing", "phishing", 0.85)
    ).check_url("https://bad.com/login")

    assert_equal "phishing", result[:verdict]
    assert_equal 1, result[:details][:failed_services].size
  end
end
