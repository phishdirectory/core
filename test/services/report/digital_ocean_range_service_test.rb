# frozen_string_literal: true

require "test_helper"

# The pipeline only reports a domain to DigitalOcean when the domain resolves
# into DigitalOcean address space, so the range list is what makes the contact
# reachable at all. A stale or empty list silently stops those reports.
class Report::DigitalOceanRangeServiceTest < ActiveSupport::TestCase
  CSV_BODY = <<~CSV
    5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH
    24.144.64.0/22,US,US-NJ,North Bergen,07047
    2604:a880::/32,US,US-NJ,North Bergen,07047
  CSV

  setup do
    @contact = create_test_abuse_contact(
      name: Report::DigitalOceanRangeService::CONTACT_NAME,
      email: "abuse@digitalocean.com",
      accepts_xarf: true
    )
  end

  def stub_ranges(body:, status: 200)
    stub_request(:get, Report::DigitalOceanRangeService::RANGES_URL)
      .to_return(status: status, body: body, headers: { "Content-Type" => "text/csv" })
  end

  test "the published ranges land on the contact" do
    stub_ranges(body: CSV_BODY)

    result = Report::DigitalOceanRangeService.new.sync

    assert result[:success]
    assert_equal 3, result[:ranges]
    assert_equal [ "5.101.96.0/21", "24.144.64.0/22", "2604:a880::/32" ], @contact.reload.ip_ranges
  end

  test "a synced range makes a domain in that space match the contact" do
    stub_ranges(body: CSV_BODY)
    Report::DigitalOceanRangeService.new.sync

    assert_equal @contact, Report::AbuseContact.find_for_ip([ "24.144.65.10" ])
  end

  test "rows that are not CIDR blocks are dropped rather than stored" do
    stub_ranges(body: "not-a-range,US\n24.144.64.0/22,US\n\n")

    result = Report::DigitalOceanRangeService.new.sync

    assert result[:success]
    assert_equal [ "24.144.64.0/22" ], @contact.reload.ip_ranges
  end

  test "an empty list leaves the existing ranges alone" do
    @contact.update!(ip_ranges: [ "24.144.64.0/22" ])
    stub_ranges(body: "\n")

    result = Report::DigitalOceanRangeService.new.sync

    assert_not result[:success]
    assert_equal [ "24.144.64.0/22" ], @contact.reload.ip_ranges
  end

  test "a failed fetch is reported instead of raising" do
    stub_ranges(body: "boom", status: 500)

    result = Report::DigitalOceanRangeService.new.sync

    assert_not result[:success]
    assert result[:error].present?
  end

  test "a missing contact is reported instead of raising" do
    @contact.destroy!
    stub_ranges(body: CSV_BODY)

    result = Report::DigitalOceanRangeService.new.sync

    assert_not result[:success]
    assert_includes result[:error], "not seeded"
  end
end
