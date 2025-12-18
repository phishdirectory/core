# frozen_string_literal: true

module Report
  class OpsMailer < ApplicationMailer
    default from: email_address_with_name("reports@transactional.phish.directory", "phish.directory Reports"),
            to: -> { team_email }

    def manual_review_needed
      @case = params[:case]

      mail(
        subject: env_subject("[MANUAL REVIEW] Case #{@case.case_number} requires attention")
      )
    end

    def case_escalated
      @case = params[:case]
      @reason = params[:reason]

      mail(
        subject: env_subject("[ESCALATED] Case #{@case.case_number}")
      )
    end

    def daily_report_summary
      @date = params[:date] || Date.yesterday
      @cases_created = Report::Case.where(created_at: @date.all_day).count
      @cases_resolved = Report::Case.where(resolved_at: @date.all_day).count
      @submissions_sent = Report::Submission.where(sent_at: @date.all_day).count
      @pending_manual_review = Report::Case.needs_manual_review.count

      mail(
        subject: env_subject("[DAILY REPORT] #{@date.strftime('%Y-%m-%d')} Summary")
      )
    end

    private

    def team_email
      Rails.application.credentials.dig(:reporting, :cc_email) || "team@phish.directory"
    end
  end
end
