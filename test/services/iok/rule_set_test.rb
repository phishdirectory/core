# frozen_string_literal: true

require "test_helper"

class Iok::RuleSetTest < ActiveSupport::TestCase
  setup do
    Iok::Indicator.with_discarded.delete_all
    Iok::RuleSet.reset!
  end

  teardown { Iok::RuleSet.reset! }

  def create_indicator(slug:, contains: "kit-marker", **attrs)
    Iok::Indicator.create!({
      slug: slug,
      title: slug.titleize,
      content_digest: SecureRandom.hex(8),
      detection: { "marker" => { "html|contains" => contains }, "condition" => "marker" }
    }.merge(attrs))
  end

  test "holds every enabled indicator" do
    create_indicator(slug: "first-kit")
    create_indicator(slug: "second-kit")

    assert_equal 2, Iok::RuleSet.current.size
  end

  test "excludes disabled and discarded indicators" do
    create_indicator(slug: "kept-kit")
    create_indicator(slug: "disabled-kit", enabled: false)
    create_indicator(slug: "gone-kit").discard

    assert_equal 1, Iok::RuleSet.current.size
  end

  test "returns the indicators whose rules matched" do
    create_indicator(slug: "first-kit", contains: "alpha")
    create_indicator(slug: "second-kit", contains: "beta")

    matches = Iok::RuleSet.current.matches("html" => [ "alpha only" ])

    assert_equal [ "first-kit" ], matches.map(&:slug)
  end

  test "an empty table gives an empty rule set" do
    assert_predicate Iok::RuleSet.current, :empty?
  end

  # ===========================================
  # Caching
  # ===========================================

  test "reuses the compiled rule set between calls" do
    create_indicator(slug: "first-kit")

    assert_same Iok::RuleSet.current, Iok::RuleSet.current
  end

  test "rebuilds when an indicator is added" do
    create_indicator(slug: "first-kit")
    before = Iok::RuleSet.current

    create_indicator(slug: "second-kit")

    assert_not_same before, Iok::RuleSet.current
    assert_equal 2, Iok::RuleSet.current.size
  end

  test "rebuilds when an indicator changes" do
    indicator = create_indicator(slug: "first-kit", contains: "alpha")
    Iok::RuleSet.current

    indicator.update!(detection: { "marker" => { "html|contains" => "beta" }, "condition" => "marker" })

    assert_equal [ "first-kit" ], Iok::RuleSet.current.matches("html" => [ "beta" ]).map(&:slug)
  end

  test "rebuilds when an indicator is discarded" do
    create_indicator(slug: "first-kit")
    create_indicator(slug: "second-kit").discard

    assert_equal 1, Iok::RuleSet.current.size
  end

  test "reset drops the cache" do
    create_indicator(slug: "first-kit")
    before = Iok::RuleSet.current

    Iok::RuleSet.reset!

    assert_not_same before, Iok::RuleSet.current
  end
end
