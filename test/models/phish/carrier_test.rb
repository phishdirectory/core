# frozen_string_literal: true

require "test_helper"

class Phish::CarrierTest < ActiveSupport::TestCase
  test "validates presence of name" do
    carrier = Phish::Carrier.new(name: nil)
    assert_not carrier.valid?
    assert_includes carrier.errors[:name], "can't be blank"
  end

  test "validates uniqueness of name" do
    Phish::Carrier.create!(name: "Verizon")
    carrier = Phish::Carrier.new(name: "Verizon")
    assert_not carrier.valid?
    assert_includes carrier.errors[:name], "has already been taken"
  end

  test "normalizes name by stripping whitespace" do
    carrier = Phish::Carrier.create!(name: "  AT&T  ")
    assert_equal "AT&T", carrier.name
  end

  test "validates carrier_type inclusion" do
    carrier = Phish::Carrier.new(name: "Test", carrier_type: "invalid")
    assert_not carrier.valid?
    assert_includes carrier.errors[:carrier_type], "is not included in the list"
  end

  test "allows valid carrier_types" do
    %w[mobile voip landline toll_free unknown].each do |type|
      carrier = Phish::Carrier.new(name: "Test #{type}", carrier_type: type)
      assert carrier.valid?, "Expected #{type} to be valid"
    end
  end

  test "generates public_id with car prefix" do
    carrier = Phish::Carrier.create!(name: "Test Carrier")
    assert carrier.public_id.start_with?("car_")
  end

  test "find_or_create_by_name creates new carrier" do
    assert_difference "Phish::Carrier.count", 1 do
      carrier = Phish::Carrier.find_or_create_by_name("New Carrier")
      assert_equal "New Carrier", carrier.name
    end
  end

  test "find_or_create_by_name returns existing carrier" do
    existing = Phish::Carrier.create!(name: "Existing")

    assert_no_difference "Phish::Carrier.count" do
      carrier = Phish::Carrier.find_or_create_by_name("Existing")
      assert_equal existing.id, carrier.id
    end
  end

  test "type helper methods work correctly" do
    carrier = Phish::Carrier.new(name: "Test")

    carrier.carrier_type = "mobile"
    assert carrier.mobile?
    assert_not carrier.voip?

    carrier.carrier_type = "voip"
    assert carrier.voip?
    assert_not carrier.mobile?

    carrier.carrier_type = "landline"
    assert carrier.landline?

    carrier.carrier_type = "toll_free"
    assert carrier.toll_free?
  end

  test "scopes filter by carrier_type" do
    mobile = Phish::Carrier.create!(name: "Mobile Carrier", carrier_type: "mobile")
    voip = Phish::Carrier.create!(name: "VOIP Carrier", carrier_type: "voip")

    assert_includes Phish::Carrier.mobile, mobile
    assert_not_includes Phish::Carrier.mobile, voip

    assert_includes Phish::Carrier.voip, voip
    assert_not_includes Phish::Carrier.voip, mobile
  end

  test "in_country scope filters by country_code" do
    us_carrier = Phish::Carrier.create!(name: "US Carrier", country_code: "US")
    uk_carrier = Phish::Carrier.create!(name: "UK Carrier", country_code: "GB")

    assert_includes Phish::Carrier.in_country("US"), us_carrier
    assert_not_includes Phish::Carrier.in_country("US"), uk_carrier
  end

  test "supports soft delete" do
    carrier = Phish::Carrier.create!(name: "To Delete")
    carrier.discard

    assert carrier.discarded?
    assert_not_includes Phish::Carrier.kept, carrier
    # Need to use with_discarded to bypass default scope
    assert_includes Phish::Carrier.with_discarded.discarded, carrier
  end
end
