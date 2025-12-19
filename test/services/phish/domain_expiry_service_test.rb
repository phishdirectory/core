# frozen_string_literal: true

require "test_helper"

class Phish::DomainExpiryServiceTest < ActiveSupport::TestCase
  setup do
    @service = Phish::DomainExpiryService.new
  end

  test "lookup returns cached result if fresh" do
    # Create a fresh cached record
    record = Phish::DomainRegistration.create!(
      domain: "example.com",
      registrar: "Test Registrar",
      registered_at: 1.year.ago,
      expires_at: 1.year.from_now,
      queried_at: 1.hour.ago
    )

    result = @service.lookup("example.com")

    assert_equal "example.com", result[:domain]
    assert_equal "Test Registrar", result[:registrar]
  end

  test "lookup normalizes domain" do
    record = Phish::DomainRegistration.create!(
      domain: "example.com",
      registrar: "Test Registrar",
      queried_at: 1.hour.ago
    )

    # Various formats should all find the same record
    assert_equal "example.com", @service.lookup("https://example.com/path")[:domain]
    assert_equal "example.com", @service.lookup("EXAMPLE.COM")[:domain]
    assert_equal "example.com", @service.lookup("example.com:8080")[:domain]
  end

  test "lookup calculates domain_age_days correctly" do
    record = Phish::DomainRegistration.create!(
      domain: "example.com",
      registered_at: 100.days.ago,
      queried_at: 1.hour.ago
    )

    result = @service.lookup("example.com")

    assert_equal 100, result[:domain_age_days]
  end

  test "lookup calculates days_until_expiry correctly" do
    record = Phish::DomainRegistration.create!(
      domain: "example.com",
      expires_at: 100.days.from_now,
      queried_at: 1.hour.ago
    )

    result = @service.lookup("example.com")

    # Allow for slight rounding differences
    assert_in_delta 100, result[:days_until_expiry], 1
  end

  test "bulk_lookup returns results for multiple domains" do
    Phish::DomainRegistration.create!(
      domain: "example1.com",
      registrar: "Registrar 1",
      queried_at: 1.hour.ago
    )
    Phish::DomainRegistration.create!(
      domain: "example2.com",
      registrar: "Registrar 2",
      queried_at: 1.hour.ago
    )

    result = @service.bulk_lookup(["example1.com", "example2.com"])

    assert_equal 2, result[:results].size
    assert_equal "Registrar 1", result[:results]["example1.com"][:registrar]
    assert_equal "Registrar 2", result[:results]["example2.com"][:registrar]
  end

  test "service_name returns domain_expiry" do
    assert_equal "domain_expiry", @service.service_name
  end
end
