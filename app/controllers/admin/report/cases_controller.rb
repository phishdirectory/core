# frozen_string_literal: true

module Admin
  module Report
    class CasesController < Admin::BaseController
      before_action :set_case, only: [:show, :retry_submission, :escalate, :resolve]

      def index
        @cases = ::Report::Case
          .includes(:submissions, :reportable)
          .order(created_at: :desc)
          .page(params[:page])

        # Filter by status
        if params[:status].present?
          @cases = @cases.where(status: params[:status])
        end

        # Filter by manual review
        if params[:manual_review] == "true"
          @cases = @cases.needs_manual_review
        end

        # Search by case number or domain
        if params[:q].present?
          @cases = @cases
            .left_joins("LEFT JOIN phish_domains ON phish_domains.id = report_cases.reportable_id AND report_cases.reportable_type = 'Phish::Domain'")
            .where("report_cases.case_number ILIKE :q OR phish_domains.domain ILIKE :q", q: "%#{params[:q]}%")
        end
      end

      def show
        @submissions = @case.submissions.includes(:abuse_contact).order(created_at: :asc)
        @emails = @case.emails.order(received_at: :desc)
      end

      # POST /admin/report/cases/:id/retry_submission
      def retry_submission
        submission_id = params[:submission_id]
        submission = @case.submissions.find_by_public_id!(submission_id)

        if submission.status_failed? && submission.may_retry_submission?
          submission.retry_submission!
          ::Report::SubmitReportJob.perform_later(submission.id)

          redirect_to admin_report_case_path(@case),
                      notice: "Submission queued for retry."
        else
          redirect_to admin_report_case_path(@case),
                      alert: "Cannot retry this submission."
        end
      end

      # POST /admin/report/cases/:id/escalate
      def escalate
        if @case.may_escalate?
          @case.escalate!

          ::Report::OpsMailer.with(case: @case, reason: "Manual escalation by #{current_user.email}")
            .case_escalated
            .deliver_later

          redirect_to admin_report_case_path(@case),
                      notice: "Case escalated. Team has been notified."
        else
          redirect_to admin_report_case_path(@case),
                      alert: "Cannot escalate this case."
        end
      end

      # POST /admin/report/cases/:id/resolve
      def resolve
        if @case.may_resolve?
          @case.resolve!

          redirect_to admin_report_case_path(@case),
                      notice: "Case marked as resolved."
        else
          redirect_to admin_report_case_path(@case),
                      alert: "Cannot resolve this case."
        end
      end

      private

      def set_case
        @case = ::Report::Case.find_by_public_id!(params[:id])
      end
    end
  end
end
