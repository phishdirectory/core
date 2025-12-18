# frozen_string_literal: true

module Report
  class AbuseReportMailer < ApplicationMailer
    default from: email_address_with_name("reports@transactional.phish.directory", "phish.directory Abuse Reports")

    def abuse_report
      @submission = params[:submission]
      @case = params[:case]
      @contact = params[:contact]
      @payload = @submission.payload

      mail(
        to: @contact.email,
        cc: @case.email_address, # case_xxx@cases.phish.directory for reply threading
        subject: env_subject("[Phishing Report] #{@case.domain_name} - Case #{@case.case_number}")
      )
    end
  end
end
