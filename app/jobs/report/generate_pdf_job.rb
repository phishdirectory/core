# frozen_string_literal: true

module Report
  # Generates a PDF for cases requiring manual review
  # (when no abuse contacts could be found)
  class GeneratePdfJob < ApplicationJob
    queue_as QUEUE_MAINTENANCE

    def perform(case_id)
      report_case = Report::Case.find_by(id: case_id)

      unless report_case
        Rails.logger.warn("[Report::GeneratePdfJob] Case not found: #{case_id}")
        return
      end

      unless report_case.requires_manual_review?
        Rails.logger.info("[Report::GeneratePdfJob] Case #{report_case.case_number} does not require manual review")
        return
      end

      Rails.logger.info("[Report::GeneratePdfJob] Generating PDF for case #{report_case.case_number}")

      # Generate actual PDF using wicked_pdf
      result = Report::PdfGeneratorService.new(report_case).generate!

      if result[:success]
        Rails.logger.info("[Report::GeneratePdfJob] PDF generated: #{result[:filename]}")

        # Send notification to team with PDF attached
        Report::TeamNotificationMailer.with(
          case: report_case,
          reason: "No abuse contacts found for domain"
        ).manual_review_required.deliver_later

        Rails.logger.info("[Report::GeneratePdfJob] Team notification sent for case #{report_case.case_number}")
      else
        Rails.logger.error("[Report::GeneratePdfJob] PDF generation failed: #{result[:error]}")

        # Send notification without PDF attachment
        Report::TeamNotificationMailer.with(
          case: report_case,
          reason: "No abuse contacts found (PDF generation failed: #{result[:error]})"
        ).manual_review_required.deliver_later
      end
    end
  end
end
