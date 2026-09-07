# frozen_string_literal: true

require "test_helper"

class Phish::IokServiceTest < ActiveSupport::TestCase
  setup do
    Iok::Indicator.with_discarded.delete_all
    Iok::RuleSet.reset!
  end

  teardown { Iok::RuleSet.reset! }

  def create_indicator(slug: "example-kit", detection: nil, **attrs)
    Iok::Indicator.create!({
      slug: slug,
      title: "Example Kit",
      content_digest: SecureRandom.hex(8),
      tags: %w[kit target.example],
      detection: detection || {
        "marker" => { "html|contains" => "kit-marker" },
        "condition" => "marker"
      }
    }.merge(attrs))
  end

  def stub_page(body)
    stub_request(:get, "https://evil.test/")
      .to_return(status: 200, body: body, headers: { "Content-Type" => "text/html" })
  end

  def service
    Phish::IokService.new
  end

  # ===========================================
  # Matching
  # ===========================================

  test "reports phishing when an indicator matches" do
    create_indicator
    stub_page("<html><body>kit-marker</body></html>")

    result = service.check_url("https://evil.test/")

    assert_equal "phishing", result[:verdict]
    assert_equal Phish::IokService::MATCH_CONFIDENCE, result[:confidence]
    assert_equal [ "example-kit" ], result[:details][:matched_indicators].map { |m| m[:slug] }
    assert_equal 1, result[:details][:indicators_evaluated]
  end

  test "reports every indicator that matched" do
    create_indicator(slug: "first-kit")
    create_indicator(
      slug: "second-kit",
      detection: { "marker" => { "title|contains" => "Sign in" }, "condition" => "marker" }
    )
    stub_page("<html><head><title>Sign in</title></head><body>kit-marker</body></html>")

    result = service.check_url("https://evil.test/")

    assert_equal %w[first-kit second-kit],
                 result[:details][:matched_indicators].map { |m| m[:slug] }.sort
  end

  # No rule matching means nobody has fingerprinted this kit yet, not that the
  # page is clean, so the result must not vote against the other services.
  test "reports unknown with no confidence when nothing matches" do
    create_indicator
    stub_page("<html><body>an ordinary page</body></html>")

    result = service.check_url("https://evil.test/")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
    assert_empty result[:details][:matched_indicators]
  end

  test "skips the fetch entirely when no indicators are loaded" do
    result = service.check_url("https://evil.test/")

    assert_equal "unknown", result[:verdict]
    assert_equal 0, result[:details][:indicators_evaluated]
    assert_not_requested :get, "https://evil.test/"
  end

  test "a disabled indicator is not evaluated" do
    create_indicator(enabled: false)
    stub_page("<html><body>kit-marker</body></html>")

    assert_equal "unknown", service.check_url("https://evil.test/")[:verdict]
  end

  # ===========================================
  # Severity
  # ===========================================

  test "a suspicious indicator reports suspicious, not phishing" do
    create_indicator(severity: Iok::Severity::SUSPICIOUS)
    stub_page("<html><body>kit-marker</body></html>")

    result = service.check_url("https://evil.test/")

    assert_equal "suspicious", result[:verdict]
    assert_equal 0.5, result[:confidence]
    assert_equal Iok::Severity::SUSPICIOUS, result[:details][:severity]
  end

  # webflow-website-creator upstream matches every Webflow site there is, so an
  # identification rule must never put a verdict behind a page on its own.
  test "an informational indicator records the match but casts no verdict" do
    create_indicator(severity: Iok::Severity::INFORMATIONAL)
    stub_page("<html><body>kit-marker</body></html>")

    result = service.check_url("https://evil.test/")

    assert_equal "unknown", result[:verdict]
    assert_equal 0.0, result[:confidence]
    assert_equal [ "example-kit" ], result[:details][:matched_indicators].map { |m| m[:slug] }
    assert_match(/carry no verdict/, result[:details][:reason])
  end

  test "the most severe matching indicator decides the verdict" do
    create_indicator(slug: "builder-kit", severity: Iok::Severity::INFORMATIONAL)
    create_indicator(
      slug: "real-kit",
      severity: Iok::Severity::MALICIOUS,
      detection: { "marker" => { "html|contains" => "kit-marker" }, "condition" => "marker" }
    )
    stub_page("<html><body>kit-marker</body></html>")

    result = service.check_url("https://evil.test/")

    assert_equal "phishing", result[:verdict]
    assert_equal 2, result[:details][:matched_indicators].size
  end

  test "an admin override beats the derived severity" do
    create_indicator(severity: Iok::Severity::MALICIOUS,
                     severity_override: Iok::Severity::INFORMATIONAL)
    stub_page("<html><body>kit-marker</body></html>")

    assert_equal "unknown", service.check_url("https://evil.test/")[:verdict]
  end

  # ===========================================
  # Domains
  # ===========================================

  test "checks a domain over https" do
    create_indicator
    stub_page("<html><body>kit-marker</body></html>")

    assert_equal "phishing", service.check_domain("evil.test")[:verdict]
  end

  test "strips a scheme and path from a domain" do
    create_indicator
    stub_page("<html><body>kit-marker</body></html>")

    assert_equal "phishing", service.check_domain("http://evil.test/login")[:verdict]
  end

  test "rejects an empty domain" do
    create_indicator

    assert_raises(Phish::BaseService::ServiceError) { service.check_domain("  ") }
  end

  # ===========================================
  # Failures
  # ===========================================

  test "a fetch failure becomes a service error" do
    create_indicator
    stub_request(:get, "https://evil.test/").to_timeout

    assert_raises(Phish::BaseService::ServiceError) { service.check_url("https://evil.test/") }
  end

  test "an internal address becomes a service error" do
    create_indicator

    error = assert_raises(Phish::BaseService::ServiceError) { service.check_url("http://127.0.0.1/") }

    assert_match(/refused to fetch/, error.message)
  end

  # One broken rule must not lose the verdicts of every other rule.
  test "an indicator that raises is skipped" do
    create_indicator
    exploding = create_indicator(slug: "exploding-kit")
    exploding.rule.define_singleton_method(:matches?) { |_| raise "boom" }

    Iok::RuleSet.stub(:current, Iok::RuleSet.new([ [ exploding, exploding.rule ] ])) do
      stub_page("<html><body>kit-marker</body></html>")

      assert_equal "unknown", service.check_url("https://evil.test/")[:verdict]
    end
  end

  # ===========================================
  # Registration
  # ===========================================

  test "is registered with the service factory" do
    assert_instance_of Phish::IokService, Phish::ServiceFactory.build(:iok)
  end

  test "is checked by default in the aggregator" do
    assert_includes Phish::AggregatorService::DEFAULT_SERVICES, :iok
  end

  test "names itself iok" do
    assert_equal "iok", service.service_name
  end
end
