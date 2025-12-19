# frozen_string_literal: true

module Report
  class AbuseReportMailer < ApplicationMailer
    default from: email_address_with_name("reports@transactional.phish.directory", "phish.directory Abuse Reports")

    def abuse_report
      @submission = params[:submission]
      @case = params[:case]
      @contact = params[:contact]
      @payload = (@submission.payload.presence || @submission.build_payload).with_indifferent_access

      # No env_subject - reports are always sent to real external contacts
      # regardless of environment (only legit phishing domains are reported)
      mail(
        to: @contact.email,
        cc: @case.email_address, # case_xxx@cases.phish.directory for reply threading
        reply_to: [
          "support@phish.directory",
          @case.email_address
        ],
        subject: "[Automated] [Phishing Report] #{@case.domain_name} - Case #{@case.case_number}"
      )
    end
  end
end
