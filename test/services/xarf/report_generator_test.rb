# frozen_string_literal: true

require "test_helper"

# DigitalOcean parses the xarf.json attachment with automated tooling and drops
# the report if it does not validate, so the document has to match schema 3 of
# https://github.com/abusix/xarf exactly. The admin UI renders the same
# document, so there is one representation rather than two that disagree.
class Xarf::ReportGeneratorTest < ActiveSupport::TestCase
  setup do
    @contact = create_test_abuse_contact(accepts_xarf: true)
    @generator = Xarf::ReportGenerator.new
  end

  def build(report_case)
    @generator.generate_for_submission(create_test_submission(report_case, @contact))
  end

  # ---------------------------------------------------------------- envelope

  test "the document carries the fields the schema requires" do
    report = build(create_test_report_case)

    assert_equal "3", report["Version"]
    assert_equal true, report["Disclosure"]
    assert report["ReporterInfo"].present?
    assert report["Report"].present?
  end

  test "the version is the newest published schema, not an invented one" do
    assert_equal "3", Xarf::ReportGenerator::SCHEMA_VERSION
    assert_includes Xarf::ReportParser::SUPPORTED_VERSIONS, "3"
  end

  test "a phishing report is classed as content" do
    report = build(create_test_report_case)["Report"]

    assert_equal "Content", report["ReportClass"]
    assert_equal "Phishing", report["ReportType"]
    assert_equal true, report["Ongoing"]
  end

  test "ReporterInfo carries only keys the schema allows" do
    allowed = %w[
      ReporterType ReporterOrg ReporterOrgDomain ReporterOrgEmail
      ReporterOrgAddress ReporterContactEmail ReporterContactName
      ReporterContactPhone
    ]

    reporter = build(create_test_report_case)["ReporterInfo"]

    assert_empty reporter.keys - allowed
    assert_equal "phish.directory", reporter["ReporterOrg"]
    assert_equal "phish.directory", reporter["ReporterOrgDomain"]
    assert reporter["ReporterOrgEmail"].present?
  end

  test "replies to the reporter contact thread back onto the case" do
    report_case = create_test_report_case
    reporter = build(report_case)["ReporterInfo"]

    assert_equal report_case.email_address, reporter["ReporterContactEmail"]
  end

  # ------------------------------------------------------------------ source

  test "a domain-only report still carries a SourceUrl" do
    report_case = create_test_report_case
    report = build(report_case)["Report"]

    assert_equal "https://#{report_case.domain_name}", report["SourceUrl"]
  end

  test "SourceIp comes from the addresses the domain resolves to" do
    report_case = create_test_report_case(domain_info: { "a_records" => [ "24.144.65.10" ] })

    assert_equal "24.144.65.10", build(report_case)["Report"]["SourceIp"]
  end

  test "an IPv6-only host still gets a SourceIp" do
    report_case = create_test_report_case(domain_info: { "aaaa_records" => [ "2604:a880::1" ] })

    assert_equal "2604:a880::1", build(report_case)["Report"]["SourceIp"]
  end

  test "IPv4 is preferred when the domain resolves to both" do
    report_case = create_test_report_case(
      domain_info: { "a_records" => [ "24.144.65.10" ], "aaaa_records" => [ "2604:a880::1" ] }
    )

    assert_equal "24.144.65.10", build(report_case)["Report"]["SourceIp"]
  end

  test "SourceIp is omitted rather than sent empty when nothing resolved" do
    report = build(create_test_report_case(domain_info: { "a_records" => [] }))["Report"]

    assert_not report.key?("SourceIp")
  end

  test "an unparseable address is dropped instead of failing validation" do
    report_case = create_test_report_case(domain_info: { "a_records" => [ "not-an-ip" ] })

    assert_not build(report_case)["Report"].key?("SourceIp")
  end

  # ------------------------------------------------------------------ fields

  test "the case number goes out as the reporter case id" do
    report_case = create_test_report_case
    report = build(report_case)["Report"]

    assert_equal report_case.case_number, report["ReporterCaseID"]
    assert_equal report_case.case_number, report["Custom"]["CaseReference"]
  end

  test "confidence maps onto the severity values the schema allows" do
    assert_equal "high", build(create_test_report_case(confidence: 0.95))["Report"]["ReporterSeverity"]
    assert_equal "medium", build(create_test_report_case(confidence: 0.75))["Report"]["ReporterSeverity"]
    assert_equal "low", build(create_test_report_case(confidence: 0.5))["Report"]["ReporterSeverity"]
  end

  test "Custom holds only strings and integers, as the schema demands" do
    custom = build(create_test_report_case)["Report"]["Custom"]

    assert custom.any?
    custom.each_value { |value| assert value.is_a?(String) || value.is_a?(Integer) }
  end

  test "the detection sources reach the abuse desk" do
    report_case = create_test_report_case(
      sources: [ { "service" => "VirusTotal" }, { "service" => "OpenPhish" } ]
    )
    report = build(report_case)["Report"]

    assert_equal "VirusTotal, OpenPhish", report["Custom"]["DetectionSources"]
    assert_includes report["ReporterNotes"], "VirusTotal"
  end

  test "sources recorded under a name key are read too" do
    report_case = create_test_report_case(sources: [ { "name" => "FishFish" } ])

    assert_equal "FishFish", build(report_case)["Report"]["Custom"]["DetectionSources"]
  end

  test "Date is an ISO 8601 timestamp" do
    date = build(create_test_report_case)["Report"]["Date"]

    assert_nothing_raised { Time.iso8601(date) }
  end

  test "a nil submission is rejected outright" do
    assert_raises(ArgumentError) { @generator.generate_for_submission(nil) }
  end

  # ------------------------------------------------- domain and url entrypoints

  test "a domain report validates as the same schema the mailer sends" do
    domain = Phish::Domain.create!(domain: "bad-#{SecureRandom.hex(4)}.com")
    domain.update!(verdict: Verdict.create!(classification: "phishing", confidence_score: 0.95))

    report = @generator.generate_for_domain(domain)

    assert_equal "3", report["Version"]
    assert_equal "Content", report.dig("Report", "ReportClass")
    assert_equal "https://#{domain.domain}", report.dig("Report", "SourceUrl")
  end

  test "a URL report reports the full URL as the source" do
    url = Phish::Url.create!(url: "https://bad-#{SecureRandom.hex(4)}.com/login")
    url.update!(verdict: Verdict.create!(classification: "phishing", confidence_score: 0.95))

    report = @generator.generate_for_url(url)

    assert_equal url.url, report.dig("Report", "SourceUrl")
  end

  test "a clean domain is not reportable" do
    domain = Phish::Domain.create!(domain: "good-#{SecureRandom.hex(4)}.com")
    domain.update!(verdict: Verdict.create!(classification: "clean", confidence_score: 0.99))

    assert Xarf::ReportGenerator.new.generate_for_domain(domain)[:error].present?
  end

  test "the generated document round-trips through the parser" do
    report = build(create_test_report_case)
    parser = Xarf::ReportParser.new(JSON.generate(report))

    assert parser.valid?, parser.errors.join(", ")
    assert_equal "phishing", parser.parse[:classification]
  end
end
