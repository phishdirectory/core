# frozen_string_literal: true

require "test_helper"

class Xarf::ReportParserTest < ActiveSupport::TestCase
  # Taken from samples/positive/3/phishing_sample.json in abusix/xarf.
  def valid_report(overrides = {})
    {
      "Version" => "3",
      "ReporterInfo" => {
        "ReporterOrg" => "ExampleOrg",
        "ReporterOrgDomain" => "example.com",
        "ReporterOrgEmail" => "reports@example.com"
      },
      "Disclosure" => true,
      "Report" => {
        "ReportClass" => "Content",
        "ReportType" => "Phishing",
        "Date" => "2018-02-05T14:17:10Z",
        "SourceIp" => "192.0.2.55",
        "SourceUrl" => "http://phish.example.org/index.html",
        "Ongoing" => true
      }
    }.deep_merge(overrides)
  end

  test "the published sample parses" do
    parser = Xarf::ReportParser.new(valid_report)

    assert parser.valid?, parser.errors.join(", ")
  end

  test "a JSON string parses the same as a hash" do
    parser = Xarf::ReportParser.new(JSON.generate(valid_report))

    assert parser.valid?, parser.errors.join(", ")
    assert_equal "Phishing", parser.report_type
  end

  test "the parsed report carries the fields callers need" do
    result = Xarf::ReportParser.new(valid_report).parse

    assert_equal "3", result[:version]
    assert_equal "Content", result[:report_class]
    assert_equal "Phishing", result[:report_type]
    assert_equal "phishing", result[:classification]
    assert_equal [ "http://phish.example.org/index.html" ], result[:urls]
    assert_equal [ "phish.example.org" ], result[:domains]
    assert_equal [ "192.0.2.55" ], result[:ip_addresses]
    assert_equal "ExampleOrg", result.dig(:reporter, :organization)
  end

  test "an older schema version is refused" do
    parser = Xarf::ReportParser.new(valid_report("Version" => "2"))

    assert_not parser.valid?
    assert(parser.errors.any? { |e| e.include?("Unsupported Version") })
  end

  test "the invented v4 shape is refused rather than half-parsed" do
    parser = Xarf::ReportParser.new(
      "xarf_version" => "4.0.0",
      "report_id" => SecureRandom.uuid,
      "category" => "content",
      "type" => "phishing"
    )

    assert_not parser.valid?
  end

  test "a report with neither an address nor a URL is refused" do
    report = valid_report
    report["Report"].delete("SourceIp")
    report["Report"].delete("SourceUrl")

    parser = Xarf::ReportParser.new(report)

    assert_not parser.valid?
    assert(parser.errors.any? { |e| e.include?("SourceIp or SourceUrl") })
  end

  test "a type sent under the wrong class is refused" do
    parser = Xarf::ReportParser.new(valid_report("Report" => { "ReportClass" => "Vulnerability" }))

    assert_not parser.valid?
    assert(parser.errors.any? { |e| e.include?("does not belong to") })
  end

  test "a reporter missing its organisation details is refused" do
    report = valid_report
    report["ReporterInfo"].delete("ReporterOrgEmail")

    parser = Xarf::ReportParser.new(report)

    assert_not parser.valid?
    assert(parser.errors.any? { |e| e.include?("ReporterOrgEmail") })
  end

  test "a natural person may report without organisation details" do
    parser = Xarf::ReportParser.new(
      valid_report("ReporterInfo" => { "ReporterType" => "Person" })
        .tap { |r| r["ReporterInfo"] = { "ReporterType" => "Person" } }
    )

    assert parser.valid?, parser.errors.join(", ")
  end

  test "Disclosure set to false is present, not missing" do
    parser = Xarf::ReportParser.new(valid_report("Disclosure" => false))

    assert parser.valid?, parser.errors.join(", ")
    assert_equal false, parser.parse[:disclosure]
  end

  test "a malformed date is refused" do
    parser = Xarf::ReportParser.new(valid_report("Report" => { "Date" => "yesterday" }))

    assert_not parser.valid?
  end

  test "invalid JSON is reported rather than raised" do
    parser = Xarf::ReportParser.new("{not json")

    assert_not parser.valid?
    assert_includes parser.errors, "Invalid JSON format"
  end

  test "parsing an invalid report raises" do
    assert_raises(Xarf::ReportParser::InvalidReportError) do
      Xarf::ReportParser.new({}).parse
    end
  end

  test "samples are summarised without carrying the payload" do
    report = valid_report(
      "Report" => {
        "Samples" => [
          { "ContentType" => "text/html", "Description" => "The page", "Payload" => "<html>x</html>" }
        ]
      }
    )

    sample = Xarf::ReportParser.new(report).parse[:samples].first

    assert_equal "text/html", sample[:content_type]
    assert_equal 14, sample[:payload_size]
    assert_not sample.key?(:payload)
  end
end
