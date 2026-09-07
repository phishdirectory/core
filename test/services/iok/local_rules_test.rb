# frozen_string_literal: true

require "test_helper"

# Every rule in db/iok/local has to compile. Without this the failure surfaces
# in the sync job, which logs it and carries on, so a broken rule would sit
# silently doing nothing.
class Iok::LocalRulesTest < ActiveSupport::TestCase
  PATHS = Dir.glob(Iok::SyncService::LOCAL_RULE_PATH.join("*.{yml,yaml}")).sort

  test "there is at least one local rule" do
    assert_not_empty PATHS, "expected rules in #{Iok::SyncService::LOCAL_RULE_PATH}"
  end

  PATHS.each do |path|
    slug = File.basename(path).sub(/\.ya?ml\z/i, "")

    test "#{slug} is valid yaml with the fields the sync job needs" do
      parsed = YAML.safe_load(File.read(path), permitted_classes: [ Date, Time ], aliases: false)

      assert_kind_of Hash, parsed
      assert parsed["title"].present?, "needs a title"
      assert parsed["description"].present?, "needs a description saying what it detects"
      assert_kind_of Array, parsed["references"], "needs references to the scans it was built from"
      assert_kind_of Hash, parsed["detection"]
    end

    test "#{slug} compiles into a rule" do
      parsed = YAML.safe_load(File.read(path), permitted_classes: [ Date, Time ], aliases: false)

      assert_nothing_raised do
        Iok::Rule.new(slug: slug, title: parsed["title"], detection: parsed["detection"])
      end
    end

    # A file name that does not survive slug normalisation would create a row
    # the next sync cannot find again, and so would recreate every run.
    test "#{slug} has a file name usable as a slug" do
      assert_equal slug, slug.strip.downcase
      assert_match(/\A[a-z0-9][a-z0-9-]*\z/, slug)
    end
  end
end
