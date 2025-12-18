# frozen_string_literal: true

module Report
  # Submits an individual report to an abuse contact
  class SubmitReportJob < ApplicationJob
    queue_as QUEUE_DEFAULT

    # Don't use ActiveJob retry - we manage retries ourselves via submission state
    discard_on StandardError do |job, error|
      submission = Report::Submission.find_by(id: job.arguments.first)
      if submission
        Rails.logger.error("[Report::SubmitReportJob] Submission #{submission.public_id} failed: #{error.message}")
        schedule_retry(submission, error)
      end
    end

    def perform(submission_id)
      submission = Report::Submission.find_by(id: submission_id)

      unless submission
        Rails.logger.warn("[Report::SubmitReportJob] Submission not found: #{submission_id}")
        return
      end

      # Check if submission is in valid state
      unless submission.status_pending? || submission.status_queued?
        Rails.logger.info("[Report::SubmitReportJob] Submission #{submission.public_id} not pending/queued (#{submission.status})")
        return
      end

      # Check dependency
      unless submission.dependency_satisfied?
        Rails.logger.info("[Report::SubmitReportJob] Submission #{submission.public_id} waiting for dependency")
        # Re-queue with delay
        Report::SubmitReportJob.set(wait: 1.minute).perform_later(submission_id)
        return
      end

      # Enqueue if still pending
      submission.enqueue! if submission.status_pending?

      # Submit based on contact method
      success = case submission.abuse_contact.method
      when "email"
        Report::EmailSubmissionService.new(submission).submit!
      when "api"
        Report::ApiSubmissionService.new(submission).submit!
      when "web_form"
        Report::WebFormSubmissionService.new(submission).submit!
      else
        Rails.logger.error("[Report::SubmitReportJob] Unknown contact method: #{submission.abuse_contact.method}")
        false
      end

      if success
        # Trigger dependent submissions
        submission.dependent_submissions.pending.each do |dependent|
          Report::SubmitReportJob.perform_later(dependent.id)
        end

        # Update case status
        update_case_status(submission.case)
      end
    end

    private

    def update_case_status(report_case)
      report_case.reload

      # Check if all submissions are done (sent, resolved, failed, or skipped)
      pending_count = report_case.submissions.where(status: %w[pending queued]).count

      if pending_count.zero?
        sent_count = report_case.submissions.where(status: %w[sent acknowledged]).count

        if sent_count > 0 && report_case.may_await_responses?
          report_case.await_responses!
          Rails.logger.info("[Report::SubmitReportJob] Case #{report_case.case_number} now awaiting responses")
        end
      end

      report_case.update_status_from_submissions!
    end

    # Schedule a retry for failed submissions
    def self.schedule_retry(submission, error)
      submission.record_response!(
        status_code: 0,
        body: error.message
      )

      if submission.retryable?
        wait_time = submission.retry_delay
        Report::SubmitReportJob.set(wait: wait_time).perform_later(submission.id)
        Rails.logger.info("[Report::SubmitReportJob] Scheduled retry for #{submission.public_id} in #{wait_time.inspect}")
      else
        submission.fail!("Max attempts reached: #{error.message}") if submission.may_fail?
        Rails.logger.error("[Report::SubmitReportJob] Submission #{submission.public_id} failed permanently after #{submission.attempts} attempts")
      end
    end
  end
end
