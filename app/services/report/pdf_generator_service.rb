# frozen_string_literal: true

module Report
  # Generates PDF reports for cases requiring manual review
  # Used when no matching abuse contacts are found in the database
  class PdfGeneratorService
    attr_reader :report_case, :logger

    def initialize(report_case, logger: Rails.logger)
      @report_case = report_case
      @logger = logger
    end

    def generate!
      logger.info("[PdfGenerator] Generating PDF for case #{report_case.case_number}")

      pdf_content = render_pdf
      filename = "case_report_#{report_case.case_number}_#{Time.current.strftime('%Y%m%d')}.pdf"

      # Attach to the case (uses manual_review_pdf attachment from Case model)
      report_case.manual_review_pdf.attach(
        io: StringIO.new(pdf_content),
        filename: filename,
        content_type: "application/pdf"
      )

      logger.info("[PdfGenerator] PDF generated and attached: #{filename}")

      { success: true, filename: filename }
    rescue StandardError => e
      logger.error("[PdfGenerator] Failed to generate PDF: #{e.message}")
      { success: false, error: e.message }
    end

    private

    def render_pdf
      html = ApplicationController.render(
        template: "reports/case_report",
        layout: "pdf",
        assigns: {
          report_case: report_case,
          domain: report_case.domain_name,
          url: report_case.url_value,
          verdict: report_case.verdict_snapshot,
          domain_info: report_case.domain_info,
          generated_at: Time.current
        }
      )

      WickedPdf.new.pdf_from_string(
        html,
        page_size: "Letter",
        margin: { top: 20, bottom: 20, left: 20, right: 20 },
        footer: {
          center: "phish.directory - Case #{report_case.case_number}",
          font_size: 8
        }
      )
    end
  end
end
