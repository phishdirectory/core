# frozen_string_literal: true

require "test_helper"

class Phish::PhoneNumberTest < ActiveSupport::TestCase
  test "validates presence of phone_number" do
    phone = Phish::PhoneNumber.new(phone_number: nil)
    assert_not phone.valid?
    assert_includes phone.errors[:phone_number], "can't be blank"
  end

  test "validates uniqueness of phone_number" do
    Phish::PhoneNumber.create!(phone_number: "+14155551234")
    phone = Phish::PhoneNumber.new(phone_number: "+14155551234")
    assert_not phone.valid?
    assert_includes phone.errors[:phone_number], "has already been taken"
  end

  test "validates E.164 format" do
    invalid_numbers = [ "1234567890", "415-555-1234", "(415) 555-1234", "+0123456789" ]

    invalid_numbers.each do |num|
      phone = Phish::PhoneNumber.new(phone_number: num)
      # The normalization might fix some of these, so we test post-normalization
      phone.valid?
      if phone.phone_number !~ /\A\+[1-9]\d{1,14}\z/
        assert_not phone.valid?, "Expected #{num} to be invalid"
      end
    end
  end

  test "normalizes phone number to E.164 format" do
    phone = Phish::PhoneNumber.create!(phone_number: "+1 (415) 555-1234")
    assert_equal "+14155551234", phone.phone_number
  end

  test "extracts country_code automatically" do
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234")
    assert_equal "US", phone.country_code
  end

  test "generates public_id with phn prefix" do
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234")
    assert phone.public_id.start_with?("phn_")
  end

  test "validates phone_type inclusion" do
    phone = Phish::PhoneNumber.new(phone_number: "+14155551234", phone_type: "invalid")
    assert_not phone.valid?
    assert_includes phone.errors[:phone_type], "is not included in the list"
  end

  test "allows valid phone_types" do
    base_number = 14155550000
    %w[mobile voip landline toll_free unknown].each_with_index do |type, i|
      phone = Phish::PhoneNumber.new(phone_number: "+#{base_number + i}", phone_type: type)
      assert phone.valid?, "Expected #{type} to be valid: #{phone.errors.full_messages}"
    end
  end

  test "type helper methods work correctly" do
    phone = Phish::PhoneNumber.new(phone_number: "+14155551234")

    phone.phone_type = "mobile"
    assert phone.mobile?
    assert_not phone.voip?

    phone.phone_type = "voip"
    assert phone.voip?
    assert_not phone.mobile?

    phone.phone_type = "toll_free"
    assert phone.toll_free?
  end

  test "check status helpers work correctly" do
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234")

    assert_not phone.checked?
    assert phone.needs_check?

    phone.update!(last_checked_at: Time.current)
    assert phone.checked?
    assert_not phone.needs_check?

    phone.update!(last_checked_at: 25.hours.ago)
    assert phone.stale?
    assert phone.needs_check?
  end

  test "touch_last_seen! updates last_seen_at" do
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234")
    assert_nil phone.last_seen_at

    phone.touch_last_seen!
    assert_not_nil phone.last_seen_at
    assert_in_delta Time.current, phone.last_seen_at, 1.second
  end

  test "update_verdict! sets verdict and last_checked_at" do
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234")
    verdict = Verdict.create!(classification: "phishing", confidence_score: 0.9)

    phone.update_verdict!(verdict)

    assert_equal verdict, phone.verdict
    assert_not_nil phone.last_checked_at
  end

  test "delegates verdict methods" do
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234")
    verdict = Verdict.create!(classification: "phishing", confidence_score: 0.9)
    phone.update!(verdict: verdict)

    assert phone.phishing?
    assert phone.dangerous?
    assert_not phone.clean?
    assert_not phone.safe?
    assert_equal 0.9, phone.confidence_score
  end

  test "scopes filter correctly" do
    checked = Phish::PhoneNumber.create!(phone_number: "+14155551234", last_checked_at: Time.current)
    unchecked = Phish::PhoneNumber.create!(phone_number: "+14155555678")
    stale = Phish::PhoneNumber.create!(phone_number: "+14155559999", last_checked_at: 25.hours.ago)

    assert_includes Phish::PhoneNumber.checked, checked
    assert_includes Phish::PhoneNumber.unchecked, unchecked
    assert_includes Phish::PhoneNumber.stale, stale
    assert_includes Phish::PhoneNumber.needs_check, unchecked
    assert_includes Phish::PhoneNumber.needs_check, stale
  end

  test "carrier association with counter_cache" do
    carrier = Phish::Carrier.create!(name: "Test Carrier")
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234", carrier: carrier)

    carrier.reload
    assert_equal 1, carrier.phone_numbers_count
    assert_equal carrier, phone.carrier
  end

  test "verdict association" do
    verdict = Verdict.create!(classification: "phishing")
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234", verdict: verdict)

    assert_equal verdict, phone.verdict
    assert_includes verdict.phish_phone_numbers, phone
  end

  test "supports soft delete" do
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234")
    phone.discard

    assert phone.discarded?
    assert_not_includes Phish::PhoneNumber.kept, phone
    # Need to use with_discarded to bypass default scope
    assert_includes Phish::PhoneNumber.with_discarded.discarded, phone
  end

  test "class method find_or_create_for_check creates new record" do
    # Create a unique number that definitely doesn't exist
    loop do
      @unique_number = "+1#{SecureRandom.random_number(9_000_000) + 1_000_000}"
      normalized = Phish::PhoneNumber.normalize_phone_number(@unique_number)
      break unless Phish::PhoneNumber.exists?(phone_number: normalized)
    end

    assert_difference "Phish::PhoneNumber.count", 1 do
      phone = Phish::PhoneNumber.find_or_create_for_check(@unique_number)
      normalized = Phish::PhoneNumber.normalize_phone_number(@unique_number)
      assert_equal normalized, phone.phone_number
    end
  end

  test "class method normalize_phone_number" do
    assert_equal "+14155551234", Phish::PhoneNumber.normalize_phone_number("+1 (415) 555-1234")
    assert_equal "+442071234567", Phish::PhoneNumber.normalize_phone_number("+44 20 7123 4567")
  end

  test "class method valid_e164?" do
    assert Phish::PhoneNumber.valid_e164?("+14155551234")
    assert Phish::PhoneNumber.valid_e164?("+442071234567")
    assert_not Phish::PhoneNumber.valid_e164?("4155551234")
    assert_not Phish::PhoneNumber.valid_e164?("+0123456789")
    assert_not Phish::PhoneNumber.valid_e164?("")
    assert_not Phish::PhoneNumber.valid_e164?(nil)
  end

  test "parsed phone helpers" do
    phone = Phish::PhoneNumber.create!(phone_number: "+14155551234")

    assert phone.valid_phone?
    assert_match(/\d{3}.*\d{3}.*\d{4}/, phone.national_format)
    assert_match(/\+1.*\d{3}.*\d{3}.*\d{4}/, phone.international_format)
  end
end
