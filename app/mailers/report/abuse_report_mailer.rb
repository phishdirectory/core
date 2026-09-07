# frozen_string_literal: true

module Report
  class AbuseReportMailer < ApplicationMailer
    default from: email_address_with_name("reports@transactional.phish.directory", "phish.directory Abuse Reports")

    def abuse_report
      @submission = params[:submission]
      @case = params[:case]
      @contact = params[:contact]
      @payload = (@submission.payload.presence || @submission.build_payload).with_indifferent_access

      @contact.accepts_xarf? ? xarf_report_mail : standard_report_mail
    end

    private

    def mail_headers
      {
        to: @contact.email,
        cc: @case.email_address, # case_xxx@cases.phish.directory for reply threading
        reply_to: [
          "support@phish.directory",
          @case.email_address
        ],
        # No env_subject - reports are always sent to real external contacts
        # regardless of environment (only legit phishing domains are reported)
        subject: "[Automated] [Phishing Report] #{@case.domain_name} - Case #{@case.case_number}"
      }
    end

    def standard_report_mail
      mail(**mail_headers)
    end

    # Build the report the way https://github.com/abusix/xarf specifies for
    # SMTP: an RFC 5965 feedback report whose third part carries the machine
    # readable document.
    #
    #   multipart/report; report-type=feedback-report
    #     text/plain              the human readable report
    #     message/feedback-report Feedback-Type: xarf, so an ARF parser stops
    #                             here and an X-ARF parser reads the next part
    #     application/json        xarf.json, the report itself
    #
    # The HTML part is left out on purpose. RFC 6522 puts the human readable
    # part first, and a lone text/plain keeps the structure identical to the
    # published example, which is what these parsers are written against.
    def xarf_report_mail
      message = mail(**mail_headers) do |format|
        format.text { render "abuse_report" }
      end

      message.add_part(feedback_report_part)
      message.attachments["xarf.json"] = {
        mime_type: "application/json",
        content: JSON.pretty_generate(
          Xarf::ReportGenerator.new.generate_for_submission(@submission)
        )
      }

      # add_part set a boundary while wrapping the body, so reuse it rather
      # than letting the new Content-Type drop it.
      message.content_type =
        %(multipart/report; report-type=feedback-report; boundary="#{message.body.boundary}")

      message
    end

    def feedback_report_part
      Mail::Part.new do
        content_type "message/feedback-report"
        content_disposition "inline"
        body [
          "Feedback-Type: xarf",
          "User-Agent: phish.directory/#{ENV.fetch('RELEASE_VERSION', '1.0.0')}",
          "Version: 1"
        ].join("\r\n")
      end
    end
  end
end
