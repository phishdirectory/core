# frozen_string_literal: true

require "test_helper"

class Report::DomainLookupTest < ActiveSupport::TestCase
  def lookup_for(attrs = {})
    Report::DomainLookup.create!(
      { domain: "bad-#{SecureRandom.hex(4)}.com" }.merge(attrs)
    )
  end

  test "a nameserver match still wins" do
    host = create_test_abuse_contact(nameserver_patterns: [ "ns1.examplehost.com" ])
    lookup = lookup_for(nameservers: [ "ns1.examplehost.com" ])

    lookup.match_contacts!

    assert_equal host, lookup.matched_hosting_contact
  end

  test "hosting falls back to the addresses the domain resolves to" do
    host = create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])
    lookup = lookup_for(nameservers: [ "ns1.somewhere-else.com" ], a_records: [ "24.144.65.10" ])

    lookup.match_contacts!

    assert_equal host, lookup.matched_hosting_contact
  end

  test "the matched host is recorded as the hosting provider" do
    host = create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])
    lookup = lookup_for(a_records: [ "24.144.65.10" ])

    lookup.match_contacts!

    assert_equal host.name, lookup.reload.hosting_provider
  end

  test "no match leaves the hosting contact empty" do
    create_test_abuse_contact(ip_ranges: [ "24.144.64.0/22" ])
    lookup = lookup_for(a_records: [ "8.8.8.8" ])

    lookup.match_contacts!

    assert_nil lookup.matched_hosting_contact
  end

  test "an IPv6-only host is matched on its AAAA records" do
    host = create_test_abuse_contact(ip_ranges: [ "2604:a880::/32" ])
    lookup = lookup_for(a_records: [], aaaa_records: [ "2604:a880::1" ])

    lookup.match_contacts!

    assert_equal host, lookup.matched_hosting_contact
  end

  test "both address families are offered to the matcher" do
    lookup = lookup_for(a_records: [ "24.144.65.10" ], aaaa_records: [ "2604:a880::1" ])

    assert_equal [ "24.144.65.10", "2604:a880::1" ], lookup.resolved_addresses
  end

  test "the resolved addresses travel with the case summary" do
    lookup = lookup_for(a_records: [ "24.144.65.10" ], aaaa_records: [ "2604:a880::1" ])
    summary = lookup.to_summary

    assert_equal [ "24.144.65.10" ], summary[:a_records]
    assert_equal [ "2604:a880::1" ], summary[:aaaa_records]
  end
end
