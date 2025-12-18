# frozen_string_literal: true

module Report
  # Service for submitting abuse reports via email
  class EmailSubmissionService
    attr_reader :submission, :logger

    def initialize(submission, logger: Rails.logger)
      @submission = submission
      @logger = logger
    end

    def submit!
      validate_submission!

      log_info("Submitting email report to #{abuse_contact.email}")

      # Send the email
      mail = Report::AbuseReportMailer.with(
        submission: submission,
        case: report_case,
        contact: abuse_contact
      ).abuse_report

      mail.deliver_now

      # Record the outbound email
      Report::CaseEmail.create_from_outbound!(
        case_record: report_case,
        submission: submission,
        mail: mail
      )

      # Mark as sent
      submission.mark_sent!

      log_info("Successfully sent report to #{abuse_contact.email} for case #{report_case.case_number}")

      true
    rescue StandardError => e
      handle_error(e)
      false
    end

    private

    def validate_submission!
      raise ArgumentError, "Submission is nil" unless submission
      raise ArgumentError, "Not an email contact" unless abuse_contact.contact_email?
      raise ArgumentError, "Contact email is blank" if abuse_contact.email.blank?
      raise ArgumentError, "Submission not in valid state" unless submission.status_pending? || submission.status_queued?
    end

    def report_case
      @report_case ||= submission.case
    end

    def abuse_contact
      @abuse_contact ||= submission.abuse_contact
    end

    def handle_error(error)
      log_error("Failed to send email report", error)

      submission.record_attempt!(error: error.message)

      if submission.retryable?
        log_info("Submission will be retried (attempt #{submission.attempts}/#{submission.max_attempts})")
      else
        submission.fail!
        log_error("Submission failed permanently after #{submission.attempts} attempts", error)
      end
    end

    def log_info(message)
      logger.info("[EmailSubmission] #{message}")
    end

    def log_error(message, error)
      logger.error("[EmailSubmission] #{message}: #{error.message}")
    end
  end
end
