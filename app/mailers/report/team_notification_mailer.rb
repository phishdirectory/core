# frozen_string_literal: true

module Report
  class TeamNotificationMailer < ApplicationMailer
    default from: email_address_with_name("reports@transactional.phish.directory", "phish.directory Reports")
    default to: "team@phish.directory"

    # Notify team when a case requires manual review (no matching abuse contacts)
    def manual_review_required
      @case = params[:case]
      @domain = @case.domain_name
      @reason = params[:reason] || "No matching abuse contacts found"

      # Attach the PDF report if available
      if @case.manual_review_pdf.attached?
        attachments["case_report_#{@case.case_number}.pdf"] = @case.manual_review_pdf.download
      end

      mail(
        subject: "[Manual Review Required] #{@domain} - Case #{@case.case_number}"
      )
    end

    # Notify team when web form automation fails
    def web_form_failure
      @case = params[:case]
      @submission = params[:submission]
      @contact = @submission.abuse_contact
      @error = params[:error]
      @domain = @case.domain_name

      mail(
        subject: "[Web Form Failed] #{@contact.name} - Case #{@case.case_number}"
      )
    end
  end
end
