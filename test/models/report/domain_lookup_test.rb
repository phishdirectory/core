# frozen_string_literal: true

require "test_helper"

class Report::DomainLookupTest < ActiveSupport::TestCase
  def lookup_for(attrs = {})
    Report::DomainLookup.create!(
      { domain: "bad-#{SecureRandom.hex(4)}.com" }.merge(attrs)
    )
  end

  test "a nameserver match still wins" do
    host = create_test_abuse_contact(hostname_patterns: [ "ns1.examplehost.com" ])
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

  test "a CNAME target names the platform when the address does not" do
    platform = create_test_abuse_contact(hostname_patterns: [ "vercel-dns.com" ])
    # The address is a shared anycast one in nobody's published range.
    lookup = lookup_for(
      nameservers: [ "ns1.somewhere-else.com" ],
      a_records: [ "76.76.21.21" ],
      dns_records: { "CNAME" => [ "cname.vercel-dns.com." ] }
    )

    lookup.match_contacts!

    assert_equal platform, lookup.matched_hosting_contact
  end

  test "a reverse lookup names the host when nothing else does" do
    host = create_test_abuse_contact(hostname_patterns: [ "digitalocean.com" ])
    lookup = lookup_for(
      a_records: [ "24.144.65.10" ],
      dns_records: { "PTR" => { "24.144.65.10" => "droplet.digitalocean.com." } }
    )

    lookup.match_contacts!

    assert_equal host, lookup.matched_hosting_contact
  end

  test "a bare pattern covers the subdomains under it" do
    host = create_test_abuse_contact(hostname_patterns: [ "digitalocean.com" ])
    lookup = lookup_for(dns_records: { "CNAME" => [ "a.b.digitalocean.com" ] })

    lookup.match_contacts!

    assert_equal host, lookup.matched_hosting_contact
  end

  test "a pattern does not match a lookalike domain" do
    create_test_abuse_contact(hostname_patterns: [ "digitalocean.com" ])
    lookup = lookup_for(dns_records: { "CNAME" => [ "notdigitalocean.com" ] })

    lookup.match_contacts!

    assert_nil lookup.matched_hosting_contact
  end

  test "a serving hostname is tried before the address" do
    by_hostname = create_test_abuse_contact(hostname_patterns: [ "vercel-dns.com" ], priority: 30)
    create_test_abuse_contact(ip_ranges: [ "76.76.0.0/16" ], priority: 30)
    lookup = lookup_for(
      a_records: [ "76.76.21.21" ],
      dns_records: { "CNAME" => [ "cname.vercel-dns.com" ] }
    )

    lookup.match_contacts!

    assert_equal by_hostname, lookup.matched_hosting_contact
  end

  # github.com delegates to Route 53 but is served by GitHub. Matching on
  # nameservers first would send the report to Amazon.
  test "the address beats a nameserver that names a different company" do
    create_test_abuse_contact(hostname_patterns: [ "*awsdns-*" ], priority: 30)
    network = create_test_abuse_contact(ip_ranges: [ "140.82.112.0/20" ], priority: 30)
    lookup = lookup_for(
      a_records: [ "140.82.114.3" ],
      dns_records: { "NS" => [ "ns-1707.awsdns-21.co.uk" ] }
    )

    lookup.match_contacts!

    assert_equal network, lookup.matched_hosting_contact
  end

  test "a nameserver still matches when nothing stronger does" do
    dns_operator = create_test_abuse_contact(hostname_patterns: [ "cloudflare.com" ])
    lookup = lookup_for(dns_records: { "NS" => [ "doug.ns.cloudflare.com" ] })

    lookup.match_contacts!

    assert_equal dns_operator, lookup.matched_hosting_contact
  end

  test "a mail host never decides who hosts the page" do
    create_test_abuse_contact(hostname_patterns: [ "aspmx.l.google.com" ])
    lookup = lookup_for(
      dns_records: { "MX" => [ { "preference" => 1, "exchange" => "aspmx.l.google.com" } ] }
    )

    lookup.match_contacts!

    assert_nil lookup.matched_hosting_contact
  end

  test "the mail hosts are surfaced for routing the mail side by hand" do
    lookup = lookup_for(
      dns_records: { "MX" => [ { "preference" => 10, "exchange" => "mx.example.com." } ] }
    )

    assert_equal [ "mx.example.com" ], lookup.mail_hosts
    assert_equal [ "mx.example.com" ], lookup.to_summary[:mail_hosts]
  end

  test "the full record set travels with the case summary" do
    lookup = lookup_for(dns_records: { "TXT" => [ "v=spf1 include:_spf.google.com ~all" ] })

    assert_equal [ "v=spf1 include:_spf.google.com ~all" ], lookup.to_summary[:dns_records]["TXT"]
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
