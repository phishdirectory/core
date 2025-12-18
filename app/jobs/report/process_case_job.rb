# frozen_string_literal: true

module Report
  # Processes a report case by queuing its submissions
  class ProcessCaseJob < ApplicationJob
    queue_as QUEUE_DEFAULT

    def perform(case_id)
      report_case = Report::Case.find_by(id: case_id)

      unless report_case
        Rails.logger.warn("[Report::ProcessCaseJob] Case not found: #{case_id}")
        return
      end

      unless report_case.status_pending?
        Rails.logger.info("[Report::ProcessCaseJob] Case #{report_case.case_number} not pending (#{report_case.status})")
        return
      end

      Rails.logger.info("[Report::ProcessCaseJob] Processing case #{report_case.case_number}")

      # Transition to submitting
      report_case.start_submitting!

      # Queue submissions that are ready
      ready_count = 0
      report_case.submissions.ready_to_send.by_priority.find_each do |submission|
        Report::SubmitReportJob.perform_later(submission.id)
        ready_count += 1
      end

      Rails.logger.info("[Report::ProcessCaseJob] Queued #{ready_count} submissions for case #{report_case.case_number}")
    end
  end
end
