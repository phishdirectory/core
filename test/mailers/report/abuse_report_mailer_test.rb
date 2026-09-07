# frozen_string_literal: true

require "test_helper"

# DigitalOcean processes its abuse mailbox with automated tooling that only
# accepts an X-ARF attachment. The envelope follows the SMTP binding in
# https://github.com/abusix/xarf, so the structure is asserted here part by
# part: tooling on the other end reads the MIME tree, not the prose.
class Report::AbuseReportMailerTest < ActionMailer::TestCase
  def deliver_to(contact, report_case: nil)
    report_case ||= create_test_report_case(domain_info: { "a_records" => [ "24.144.65.10" ] })

    Report::AbuseReportMailer.with(
      submission: create_test_submission(report_case, contact),
      case: report_case,
      contact: contact
    ).abuse_report
  end

  test "an X-ARF contact receives a feedback report envelope" do
    mail = deliver_to(create_test_abuse_contact(accepts_xarf: true))

    assert_equal "multipart/report", mail.mime_type
    assert_equal "feedback-report", mail.content_type_parameters["report-type"]
  end

  test "the envelope holds the three parts the binding requires, in order" do
    mail = deliver_to(create_test_abuse_contact(accepts_xarf: true))

    assert_equal 3, mail.parts.size
    assert_equal "text/plain", mail.parts[0].mime_type
    assert_equal "message/feedback-report", mail.parts[1].mime_type
    assert_equal "application/json", mail.parts[2].mime_type
  end

  test "the feedback report part tells an ARF parser to expect X-ARF" do
    mail = deliver_to(create_test_abuse_contact(accepts_xarf: true))
    body = mail.parts[1].body.decoded

    assert_includes body, "Feedback-Type: xarf"
    assert_includes body, "Version: 1"
    assert_includes body, "User-Agent: phish.directory/"
  end

  test "the attachment is xarf.json and parses as an X-ARF document" do
    mail = deliver_to(create_test_abuse_contact(accepts_xarf: true))
    attachment = mail.attachments.find { |part| part.filename == "xarf.json" }

    assert attachment, "expected an xarf.json attachment"

    report = JSON.parse(attachment.body.decoded)

    assert_equal "3", report["Version"]
    assert_equal "Phishing", report.dig("Report", "ReportType")
    assert_equal "24.144.65.10", report.dig("Report", "SourceIp")
  end

  test "the human readable part still describes the report" do
    report_case = create_test_report_case
    mail = deliver_to(create_test_abuse_contact(accepts_xarf: true), report_case: report_case)

    assert_includes mail.parts[0].body.decoded, report_case.domain_name
  end

  test "the case address stays on the report so replies thread" do
    report_case = create_test_report_case
    contact = create_test_abuse_contact(accepts_xarf: true, email: "abuse@digitalocean.example")
    mail = deliver_to(contact, report_case: report_case)

    assert_equal [ "abuse@digitalocean.example" ], mail.to
    assert_equal [ report_case.email_address ], mail.cc
    assert_includes mail.subject, report_case.case_number
  end

  test "a contact that did not ask for X-ARF gets the report unchanged" do
    mail = deliver_to(create_test_abuse_contact(accepts_xarf: false))

    assert_equal "multipart/alternative", mail.mime_type
    assert_empty mail.attachments
    assert mail.html_part, "expected the HTML report to still be sent"
  end

  test "both kinds of report are deliverable" do
    xarf = deliver_to(create_test_abuse_contact(accepts_xarf: true))
    plain = deliver_to(create_test_abuse_contact(accepts_xarf: false))

    assert_nothing_raised do
      xarf.deliver_now
      plain.deliver_now
    end
    assert_equal 2, ActionMailer::Base.deliveries.size
  end
end
