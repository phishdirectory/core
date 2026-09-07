# frozen_string_literal: true

require "test_helper"

# A phishing site on platform hosting resolves to a shared anycast address that
# belongs to a CDN, not to the platform serving the page. The CNAME and the
# reverse lookup are what name the party who can take it down, so the sweep has
# to surface them for the matcher and for a human reading the case.
class Report::DnsSweepServiceTest < ActiveSupport::TestCase
  def records
    {
      "A" => [ "76.76.21.21" ],
      "AAAA" => [ "2606:4700::1" ],
      "CNAME" => [ "cname.vercel-dns.com." ],
      "NS" => [ "ns1.vercel-dns.com." ],
      "MX" => [ { "preference" => 10, "exchange" => "mx.example.com." } ],
      "PTR" => { "76.76.21.21" => "cname.vercel-dns.com." }
    }
  end

  test "the serving hostnames are the ones that name who runs the page" do
    serving = Report::DnsSweepService.serving_hostnames(records)

    assert_equal [ "cname.vercel-dns.com" ], serving
    assert_not_includes serving, "ns1.vercel-dns.com", "a nameserver is not a serving host"
    assert_not_includes serving, "mx.example.com", "a mail host is not a serving host"
  end

  test "nameservers are kept apart as the weaker signal" do
    assert_equal [ "ns1.vercel-dns.com" ], Report::DnsSweepService.nameserver_hostnames(records)
  end

  test "the combined list puts serving hostnames first" do
    hostnames = Report::DnsSweepService.hostnames(records)

    assert_operator hostnames.index("cname.vercel-dns.com"), :<,
                    hostnames.index("ns1.vercel-dns.com")
  end

  test "trailing dots are stripped so patterns match" do
    Report::DnsSweepService.hostnames(records).each do |hostname|
      assert_not hostname.end_with?("."), "#{hostname} kept its trailing dot"
    end
  end

  test "hostnames are deduplicated" do
    duplicated = { "CNAME" => [ "a.example.com." ], "NS" => [ "A.EXAMPLE.COM" ] }

    assert_equal [ "a.example.com" ], Report::DnsSweepService.hostnames(duplicated)
  end

  test "an empty sweep yields no hostnames" do
    assert_empty Report::DnsSweepService.hostnames({})
  end

  test "a blank domain is not queried" do
    assert_empty Report::DnsSweepService.new.sweep("")
    assert_empty Report::DnsSweepService.new.sweep(nil)
  end

  test "the record types swept are the ones that name a party to report to" do
    types = Report::DnsSweepService::RECORD_TYPES.keys

    assert_equal %w[A AAAA CNAME NS MX TXT SOA CAA], types
  end

  test "a domain that does not resolve yields no records rather than raising" do
    result = nil

    assert_nothing_raised do
      result = Report::DnsSweepService.new.sweep("does-not-exist-#{SecureRandom.hex(8)}.invalid")
    end
    assert_empty result
  end
end
