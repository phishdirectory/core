# frozen_string_literal: true

require "test_helper"

class Iok::IndicatorTest < ActiveSupport::TestCase
  DETECTION = {
    "marker" => { "html|contains" => "kit-marker" },
    "condition" => "marker"
  }.freeze

  setup do
    Iok::Indicator.with_discarded.delete_all
    Iok::RuleSet.reset!
  end

  teardown { Iok::RuleSet.reset! }

  def build_indicator(attrs = {})
    Iok::Indicator.new({
      slug: "example-kit",
      title: "Example Kit",
      detection: DETECTION,
      content_digest: "abc123"
    }.merge(attrs))
  end

  test "is valid with a compiling detection block" do
    assert build_indicator.valid?
  end

  test "requires a slug, a title and a digest" do
    indicator = build_indicator(slug: nil, title: nil, content_digest: nil)

    assert_not indicator.valid?
    assert_includes indicator.errors.attribute_names, :slug
    assert_includes indicator.errors.attribute_names, :title
    assert_includes indicator.errors.attribute_names, :content_digest
  end

  test "normalises the slug" do
    assert_equal "example-kit", build_indicator(slug: "  Example-Kit  ").tap(&:valid?).slug
  end

  test "rejects a duplicate slug among kept records" do
    build_indicator.save!

    assert_not build_indicator.valid?
  end

  test "allows the slug of a discarded record to be reused" do
    build_indicator.tap(&:save!).discard

    assert build_indicator.valid?
  end

  # Storing a rule that cannot compile would move the failure from the sync job
  # into an unrelated domain check.
  test "rejects a detection block that does not compile" do
    indicator = build_indicator(detection: { "marker" => { "body|contains" => "x" }, "condition" => "marker" })

    assert_not indicator.valid?
    assert_match(/unknown field/, indicator.errors[:detection].join)
  end

  test "compiles a rule from the stored detection block" do
    indicator = build_indicator

    assert indicator.matches?("html" => "a kit-marker here")
    assert_not indicator.matches?("html" => "nothing here")
  end

  test "reports whether the stored rule still compiles" do
    assert build_indicator.valid_rule?
    assert_not build_indicator(detection: {}).valid_rule?
  end

  test "summarises itself for verdict details" do
    indicator = build_indicator(tags: %w[kit target.example]).tap(&:save!)
    summary = indicator.to_match_summary

    assert_equal indicator.public_id, summary[:id]
    assert_equal "example-kit", summary[:slug]
    assert_equal %w[kit target.example], summary[:tags]
  end

  test "the enabled scope excludes disabled rows" do
    build_indicator.save!
    build_indicator(slug: "disabled-kit", enabled: false).save!

    assert_equal [ "example-kit" ], Iok::Indicator.enabled.pluck(:slug)
  end

  test "the tagged scope finds indicators by tag" do
    build_indicator(tags: %w[kit target.apple]).save!
    build_indicator(slug: "other-kit", tags: %w[malware]).save!

    assert_equal [ "example-kit" ], Iok::Indicator.tagged("target.apple").pluck(:slug)
  end
end
