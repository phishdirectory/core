# frozen_string_literal: true

module Report
  # Checks the status of a single CleanDNS submission
  # Scheduled 24 hours after submission, reschedules if not resolved
  class CheckCleandnsStatusJob < ApplicationJob
    queue_as QUEUE_MAINTENANCE

    # Stop checking after 30 days
    MAX_CHECK_DAYS = 30

    def perform(submission_id)
      submission = Report::Submission.find_by(id: submission_id)

      unless submission
        Rails.logger.info("[CheckCleandnsStatusJob] Submission #{submission_id} not found")
        return
      end

      # Skip if already resolved or failed
      unless submission.status_sent? || submission.status_acknowledged?
        Rails.logger.debug("[CheckCleandnsStatusJob] Submission #{submission.public_id} not active (#{submission.status})")
        return
      end

      # Stop checking after MAX_CHECK_DAYS
      if submission.sent_at && submission.sent_at < MAX_CHECK_DAYS.days.ago
        Rails.logger.info("[CheckCleandnsStatusJob] Submission #{submission.public_id} exceeded max check period")
        return
      end

      status_info = Report::ApiSubmissionService.check_cleandns_status(submission)

      unless status_info
        reschedule(submission_id)
        return
      end

      new_state = Report::ApiSubmissionService.cleandns_status_to_state(status_info)

      case new_state
      when :acknowledged
        if submission.status_sent? && submission.may_acknowledge?
          submission.acknowledge!
          log_state_change(submission, status_info)
          reschedule(submission_id) # Keep checking until resolved
        else
          reschedule(submission_id)
        end
      when :resolved
        if submission.may_mark_resolved?
          submission.mark_resolved!
          log_state_change(submission, status_info)
          # Done - no reschedule needed
        end
      else
        reschedule(submission_id)
      end
    rescue StandardError => e
      Rails.logger.error("[CheckCleandnsStatusJob] Error checking #{submission_id}: #{e.message}")
      reschedule(submission_id)
    end

    private

    def reschedule(submission_id)
      self.class.set(wait: 24.hours).perform_later(submission_id)
    end

    def log_state_change(submission, status_info)
      Rails.logger.info(
        "[CheckCleandnsStatusJob] Updated #{submission.public_id} to #{submission.status} " \
        "(tier: #{status_info[:tier]}, status: #{status_info[:status].join(', ')})"
      )
    end
  end
end
