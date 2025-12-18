# frozen_string_literal: true

module Report
  # Creates a report case for a detected phishing domain/URL
  # Triggered by PhishDomainCheckJob when phishing is detected with high confidence
  class CreateCaseJob < ApplicationJob
    queue_as QUEUE_DEFAULT

    def perform(reportable_type, reportable_id)
      reportable = reportable_type.constantize.find_by(id: reportable_id)

      unless reportable
        Rails.logger.warn("[Report::CreateCaseJob] Reportable not found: #{reportable_type}##{reportable_id}")
        return
      end

      unless reportable.verdict&.classification == "phishing"
        Rails.logger.info("[Report::CreateCaseJob] Skipping - not phishing: #{reportable_type}##{reportable_id}")
        return
      end

      service = Report::CaseCreationService.new(reportable, reportable.verdict)
      report_case = service.create_case!

      if report_case
        Rails.logger.info("[Report::CreateCaseJob] Created case #{report_case.case_number}")
      else
        Rails.logger.info("[Report::CreateCaseJob] No case created (threshold not met or case exists)")
      end
    end
  end
end
