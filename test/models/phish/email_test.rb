# frozen_string_literal: true

require "test_helper"

class Phish::EmailTest < ActiveSupport::TestCase
  test "validates presence of email" do
    email = Phish::Email.new(email: nil)
    assert_not email.valid?
    assert_includes email.errors[:email], "can't be blank"
  end

  test "validates uniqueness of email" do
    Phish::Email.create!(email: "test@example.com")
    email = Phish::Email.new(email: "test@example.com")
    assert_not email.valid?
    assert_includes email.errors[:email], "has already been taken"
  end

  test "validates email format" do
    invalid_emails = [ "notanemail", "missing@tld", "@nodomain.com", "spaces in@email.com" ]

    invalid_emails.each do |addr|
      email = Phish::Email.new(email: addr)
      assert_not email.valid?, "Expected #{addr} to be invalid"
    end
  end

  test "normalizes email to lowercase" do
    email = Phish::Email.create!(email: "TEST@EXAMPLE.COM")
    assert_equal "test@example.com", email.email
  end

  test "extracts domain automatically" do
    email = Phish::Email.create!(email: "user@example.com")
    assert_equal "example.com", email.domain
  end

  test "generates public_id with eml prefix" do
    email = Phish::Email.create!(email: "test@example.com")
    assert email.public_id.start_with?("eml_")
  end

  test "validates reputation_score range" do
    email = Phish::Email.new(email: "test@example.com", reputation_score: 1.5)
    assert_not email.valid?

    email.reputation_score = -0.1
    assert_not email.valid?

    email.reputation_score = 0.5
    assert email.valid?
  end

  test "check status helpers work correctly" do
    email = Phish::Email.create!(email: "test@example.com")

    assert_not email.checked?
    assert email.needs_check?

    email.update!(last_checked_at: Time.current)
    assert email.checked?
    assert_not email.needs_check?

    email.update!(last_checked_at: 25.hours.ago)
    assert email.stale?
    assert email.needs_check?
  end

  test "touch_last_seen! updates last_seen_at" do
    email = Phish::Email.create!(email: "test@example.com")
    assert_nil email.last_seen_at

    email.touch_last_seen!
    assert_not_nil email.last_seen_at
    assert_in_delta Time.current, email.last_seen_at, 1.second
  end

  test "update_verdict! sets verdict and last_checked_at" do
    email = Phish::Email.create!(email: "test@example.com")
    verdict = Verdict.create!(classification: "phishing", confidence_score: 0.9)

    email.update_verdict!(verdict)

    assert_equal verdict, email.verdict
    assert_not_nil email.last_checked_at
  end

  test "delegates verdict methods" do
    email = Phish::Email.create!(email: "test@example.com")
    verdict = Verdict.create!(classification: "phishing", confidence_score: 0.9)
    email.update!(verdict: verdict)

    assert email.phishing?
    assert email.dangerous?
    assert_not email.clean?
    assert_not email.safe?
    assert_equal 0.9, email.confidence_score
  end

  test "risky? returns true for disposable emails" do
    email = Phish::Email.create!(email: "test@example.com", disposable: true)
    assert email.risky?
  end

  test "risky? returns true for low reputation" do
    email = Phish::Email.create!(email: "test@example.com", reputation_score: 0.2)
    assert email.risky?
  end

  test "trusted? returns true for good emails" do
    email = Phish::Email.create!(
      email: "test@example.com",
      disposable: false,
      deliverable: true,
      valid_mx: true,
      reputation_score: 0.8
    )
    assert email.trusted?
  end

  test "scopes filter correctly" do
    checked = Phish::Email.create!(email: "checked@example.com", last_checked_at: Time.current)
    unchecked = Phish::Email.create!(email: "unchecked@example.com")
    stale = Phish::Email.create!(email: "stale@example.com", last_checked_at: 25.hours.ago)
    disposable_email = Phish::Email.create!(email: "disposable@temp.com", disposable: true)

    assert_includes Phish::Email.checked, checked
    assert_includes Phish::Email.unchecked, unchecked
    assert_includes Phish::Email.stale, stale
    assert_includes Phish::Email.needs_check, unchecked
    assert_includes Phish::Email.needs_check, stale
    assert_includes Phish::Email.disposable, disposable_email
  end

  test "for_domain scope filters by domain" do
    gmail = Phish::Email.create!(email: "user1@gmail.com")
    yahoo = Phish::Email.create!(email: "user2@yahoo.com")

    assert_includes Phish::Email.for_domain("gmail.com"), gmail
    assert_not_includes Phish::Email.for_domain("gmail.com"), yahoo
  end

  test "verdict association" do
    verdict = Verdict.create!(classification: "phishing")
    email = Phish::Email.create!(email: "test@example.com", verdict: verdict)

    assert_equal verdict, email.verdict
    assert_includes verdict.phish_emails, email
  end

  test "supports soft delete" do
    email = Phish::Email.create!(email: "test@example.com")
    email.discard

    assert email.discarded?
    assert_not_includes Phish::Email.kept, email
    assert_includes Phish::Email.with_discarded.discarded, email
  end

  test "class method find_or_create_for_check creates new record" do
    loop do
      @unique_email = "test#{SecureRandom.hex(4)}@example.com"
      break unless Phish::Email.exists?(email: @unique_email)
    end

    assert_difference "Phish::Email.count", 1 do
      email = Phish::Email.find_or_create_for_check(@unique_email)
      assert_equal @unique_email, email.email
    end
  end

  test "class method normalize_email" do
    assert_equal "test@example.com", Phish::Email.normalize_email("  TEST@EXAMPLE.COM  ")
  end

  test "class method valid_email?" do
    assert Phish::Email.valid_email?("test@example.com")
    assert Phish::Email.valid_email?("user.name+tag@domain.co.uk")
    assert_not Phish::Email.valid_email?("notanemail")
    assert_not Phish::Email.valid_email?("")
    assert_not Phish::Email.valid_email?(nil)
  end

  test "class method extract_domain" do
    assert_equal "example.com", Phish::Email.extract_domain("user@example.com")
    assert_equal "sub.domain.com", Phish::Email.extract_domain("user@sub.domain.com")
  end

  test "local_part returns part before @" do
    email = Phish::Email.create!(email: "username@example.com")
    assert_equal "username", email.local_part
  end

  test "domain_part returns part after @" do
    email = Phish::Email.create!(email: "username@example.com")
    assert_equal "example.com", email.domain_part
  end
end
