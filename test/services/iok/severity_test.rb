# frozen_string_literal: true

require "test_helper"

class Iok::SeverityTest < ActiveSupport::TestCase
  def derive(level: nil, tags: [])
    Iok::Severity.derive(level: level, tags: tags)
  end

  # ===========================================
  # Tags
  # ===========================================

  test "kit and malware tags are malicious" do
    assert_equal Iok::Severity::MALICIOUS, derive(tags: %w[kit target.apple])
    assert_equal Iok::Severity::MALICIOUS, derive(tags: %w[malware.amadey malware])
    assert_equal Iok::Severity::MALICIOUS, derive(tags: %w[crypto_drainer])
    assert_equal Iok::Severity::MALICIOUS, derive(tags: %w[threat_actor.someone])
  end

  # A page that cloaks or was cloned is worth looking at, but neither is a
  # verdict on its own. fake-404-page.yml upstream is tagged cloaking.
  test "technique tags are suspicious" do
    assert_equal Iok::Severity::SUSPICIOUS, derive(tags: %w[cloaking])
    assert_equal Iok::Severity::SUSPICIOUS, derive(tags: %w[anti-analysis])
    assert_equal Iok::Severity::SUSPICIOUS, derive(tags: %w[cloning])
  end

  # webflow-website-creator.yml upstream matches every Webflow site there is.
  test "tags naming benign tooling are informational" do
    assert_equal Iok::Severity::INFORMATIONAL, derive(tags: %w[website_builder.webflow])
    assert_equal Iok::Severity::INFORMATIONAL, derive(tags: %w[template_service.themetags])
  end

  # page_type says which kind of page a rule matches, not who built it.
  # facebook-54b8f7e-landing.yml upstream carries only page_type.landing and
  # target.facebook, and it is a Facebook credential kit.
  test "page_type is descriptive and does not demote a rule" do
    assert_equal Iok::Severity::MALICIOUS, derive(tags: %w[page_type.landing target.facebook])
  end

  test "the most severe tag wins" do
    assert_equal Iok::Severity::MALICIOUS, derive(tags: %w[cloaking kit])
    assert_equal Iok::Severity::SUSPICIOUS, derive(tags: %w[website_builder.webflow cloaking])
  end

  test "descriptive tags carry no severity of their own" do
    # Most of the corpus is a kit with only target tags, so the default has to
    # be malicious or those rules would silently stop reporting.
    assert_equal Iok::Severity::MALICIOUS, derive(tags: %w[target.coinbase cryptocurrency])
    assert_equal Iok::Severity::MALICIOUS, derive(tags: [])
  end

  test "tag matching uses the namespace and ignores case" do
    assert_equal Iok::Severity::MALICIOUS, derive(tags: %w[Malware.Amadey])
    assert_equal Iok::Severity::INFORMATIONAL, derive(tags: %w[WEBSITE_BUILDER.wix])
  end

  # ===========================================
  # Levels
  # ===========================================

  test "an explicit level overrides the tags" do
    assert_equal Iok::Severity::SUSPICIOUS, derive(level: "potentially_malicious", tags: %w[kit])
    assert_equal Iok::Severity::INFORMATIONAL, derive(level: "informational", tags: %w[kit])
    assert_equal Iok::Severity::MALICIOUS, derive(level: "critical", tags: %w[website_builder])
  end

  test "sigma levels map onto the three buckets" do
    assert_equal Iok::Severity::MALICIOUS, derive(level: "high")
    assert_equal Iok::Severity::SUSPICIOUS, derive(level: "medium")
    assert_equal Iok::Severity::INFORMATIONAL, derive(level: "low")
  end

  test "an unknown or blank level falls through to the tags" do
    assert_equal Iok::Severity::SUSPICIOUS, derive(level: "banana", tags: %w[cloaking])
    assert_equal Iok::Severity::SUSPICIOUS, derive(level: "  ", tags: %w[cloaking])
    assert_equal Iok::Severity::SUSPICIOUS, derive(level: nil, tags: %w[cloaking])
  end

  # ===========================================
  # Ordering
  # ===========================================

  test "highest picks the most severe" do
    assert_equal Iok::Severity::MALICIOUS,
                 Iok::Severity.highest([ Iok::Severity::INFORMATIONAL, Iok::Severity::MALICIOUS ])
    assert_equal Iok::Severity::SUSPICIOUS,
                 Iok::Severity.highest([ Iok::Severity::INFORMATIONAL, Iok::Severity::SUSPICIOUS ])
    assert_nil Iok::Severity.highest([])
  end

  test "valid? recognises only the three buckets" do
    assert Iok::Severity.valid?(Iok::Severity::MALICIOUS)
    assert_not Iok::Severity.valid?("banana")
    assert_not Iok::Severity.valid?(nil)
  end
end
