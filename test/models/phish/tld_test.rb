# frozen_string_literal: true

require "test_helper"

class Phish::TldTest < ActiveSupport::TestCase
  test "validates presence of name" do
    tld = Phish::Tld.new(name: nil)
    assert_not tld.valid?
    assert_includes tld.errors[:name], "can't be blank"
  end

  test "validates uniqueness of name" do
    Phish::Tld.create!(name: "com")
    tld = Phish::Tld.new(name: "com")
    assert_not tld.valid?
    assert_includes tld.errors[:name], "has already been taken"
  end

  test "normalizes name to lowercase" do
    tld = Phish::Tld.create!(name: "COM")
    assert_equal "com", tld.name
  end

  test "extracts simple TLD from domain" do
    assert_equal "com", Phish::Tld.extract_from_domain("example.com")
    assert_equal "org", Phish::Tld.extract_from_domain("test.org")
  end

  test "extracts compound TLD from domain" do
    assert_equal "co.uk", Phish::Tld.extract_from_domain("example.co.uk")
    assert_equal "com.au", Phish::Tld.extract_from_domain("test.com.au")
  end

  test "handles invalid domains gracefully" do
    assert_nil Phish::Tld.extract_from_domain("")
    assert_nil Phish::Tld.extract_from_domain(nil)
  end

  test "find_or_create_from_domain creates new TLD" do
    assert_difference "Phish::Tld.count", 1 do
      tld = Phish::Tld.find_or_create_from_domain("newdomain.xyz")
      assert_equal "xyz", tld.name
    end
  end

  test "find_or_create_from_domain returns existing TLD" do
    existing = Phish::Tld.create!(name: "com")

    assert_no_difference "Phish::Tld.count" do
      tld = Phish::Tld.find_or_create_from_domain("example.com")
      assert_equal existing.id, tld.id
    end
  end

  test "cleandns_supported scope" do
    supported = Phish::Tld.create!(name: "com", cleandns_supported: true)
    unsupported = Phish::Tld.create!(name: "xyz", cleandns_supported: false)

    assert_includes Phish::Tld.cleandns_supported, supported
    assert_not_includes Phish::Tld.cleandns_supported, unsupported
  end

  test "update_from_cleandns! sets all fields" do
    tld = Phish::Tld.create!(name: "com")

    tld.update_from_cleandns!(
      registrars_list: [ "GoDaddy", "Namecheap" ],
      resellers_list: [ "Reseller1" ],
      supported: true
    )

    assert tld.cleandns_supported?
    assert_equal [ "GoDaddy", "Namecheap" ], tld.registrars
    assert_equal [ "Reseller1" ], tld.resellers
    assert_not_nil tld.cleandns_synced_at
  end

  test "sync_needed? returns true when never synced" do
    tld = Phish::Tld.create!(name: "com")
    assert tld.sync_needed?
  end

  test "sync_needed? returns false when recently synced" do
    tld = Phish::Tld.create!(name: "com", cleandns_synced_at: 1.hour.ago)
    assert_not tld.sync_needed?
  end

  test "sync_needed? returns true when sync is stale" do
    tld = Phish::Tld.create!(name: "com", cleandns_synced_at: 25.hours.ago)
    assert tld.sync_needed?
  end
end
