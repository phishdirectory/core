# frozen_string_literal: true

require "test_helper"

# Hosting used to be matched on nameserver patterns alone. A phishing site on a
# DigitalOcean droplet keeps its registrar's nameservers, so that never found
# the provider serving the page. Matching the addresses the domain resolves to
# is what does.
class Report::AbuseContactTest < ActiveSupport::TestCase
  test "a contact is found when its ranges cover the address" do
    contact = create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])

    assert_equal contact, Report::AbuseContact.find_for_ip([ "24.144.65.10" ])
  end

  test "a contact outside the address range is not found" do
    create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])

    assert_nil Report::AbuseContact.find_for_ip([ "8.8.8.8" ])
  end

  test "any one of several addresses is enough to match" do
    contact = create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])

    assert_equal contact, Report::AbuseContact.find_for_ip([ "8.8.8.8", "24.144.65.10" ])
  end

  test "an inactive contact is never matched" do
    create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ], active: false)

    assert_nil Report::AbuseContact.find_for_ip([ "24.144.65.10" ])
  end

  test "the lowest priority number wins when ranges overlap" do
    create_test_abuse_contact(ip_ranges: [ "24.144.0.0/16" ], priority: 40)
    preferred = create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ], priority: 10)

    assert_equal preferred, Report::AbuseContact.find_for_ip([ "24.144.65.10" ])
  end

  test "no addresses means no match" do
    create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])

    assert_nil Report::AbuseContact.find_for_ip([])
    assert_nil Report::AbuseContact.find_for_ip(nil)
  end

  test "an unparseable address is skipped instead of raising" do
    create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])

    assert_nil Report::AbuseContact.find_for_ip([ "not-an-ip" ])
  end

  test "an unparseable range is skipped instead of raising" do
    contact = create_test_abuse_contact(ip_ranges: [ "garbage", "24.144.64.0/22" ])

    assert_equal contact, Report::AbuseContact.find_for_ip([ "24.144.65.10" ])
  end

  test "an IPv6 address does not match an IPv4 range" do
    create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])

    assert_nil Report::AbuseContact.find_for_ip([ "2604:a880::1" ])
  end

  test "an IPv6 address matches an IPv6 range" do
    contact = create_test_abuse_contact(ip_ranges: [ "2604:a880::/32" ])

    assert_equal contact, Report::AbuseContact.find_for_ip([ "2604:a880::1" ])
  end
end
