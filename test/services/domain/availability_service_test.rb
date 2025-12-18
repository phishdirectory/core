# frozen_string_literal: true

require "test_helper"

class Domain::AvailabilityServiceTest < ActiveSupport::TestCase
  test "check returns structured result" do
    # Using a well-known domain that should be resolvable
    result = Domain::AvailabilityService.check("google.com")

    assert result.is_a?(Hash)
    assert_equal "google.com", result[:domain]
    assert result[:dns].is_a?(Hash)
    assert result[:http].is_a?(Hash)
    assert_includes [true, false], result[:available]
    assert result[:checked_at].is_a?(Time)
  end

  test "normalizes domain input" do
    result = Domain::AvailabilityService.check("HTTPS://EXAMPLE.COM/path?query=1")

    assert_equal "example.com", result[:domain]
  end

  test "dns result includes addresses when resolvable" do
    result = Domain::AvailabilityService.check("google.com")

    assert result[:dns].key?(:resolvable)
    assert result[:dns].key?(:addresses)
    assert result[:dns].key?(:error)
  end

  test "http result includes status when reachable" do
    result = Domain::AvailabilityService.check("google.com")

    assert result[:http].key?(:reachable)
    assert result[:http].key?(:status)
    assert result[:http].key?(:error)
  end

  test "handles non-existent domain gracefully" do
    result = Domain::AvailabilityService.check("this-domain-definitely-does-not-exist-12345.invalid")

    assert_not result[:dns][:resolvable]
    assert_not result[:available]
    assert result[:dns][:error].present?
  end

  test "skips http check when dns fails" do
    result = Domain::AvailabilityService.check("this-domain-definitely-does-not-exist-12345.invalid")

    assert_not result[:http][:reachable]
    assert_equal "DNS not resolvable", result[:http][:error]
  end

  test "class method check works" do
    result = Domain::AvailabilityService.check("google.com", dns_timeout: 3, http_timeout: 5)

    assert result.is_a?(Hash)
    assert result[:checked_at].present?
  end
end
