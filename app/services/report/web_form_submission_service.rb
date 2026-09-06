# frozen_string_literal: true

module Report
  # Service for submitting abuse reports via web forms
  # Uses Ferrum (headless Chrome) for form automation
  #
  # Web form submissions are inherently fragile as forms change.
  # Each handler is specific to a provider's form structure.
  class WebFormSubmissionService < BaseService
    attr_reader :submission

    # Known form handlers - maps provider names to handler methods
    FORM_HANDLERS = {
      "cloudflare" => :submit_cloudflare,
      "godaddy" => :submit_godaddy,
      "namecheap" => :submit_namecheap,
      "porkbun" => :submit_porkbun,
      "namesilo" => :submit_namesilo,
      "hostinger" => :submit_hostinger,
      "vercel" => :submit_vercel
    }.freeze

    def initialize(submission, logger: Rails.logger)
      super(logger: logger)
      @submission = submission
    end

    def submit!
      validate_submission!

      log_info("Submitting web form report to #{abuse_contact.name}")

      handler = determine_handler
      unless handler
        log_info("No automated handler for #{abuse_contact.name}, marking as skipped")
        submission.skip!
        return true
      end

      success = send(handler)

      if success
        submission.mark_sent!
        log_info("Successfully submitted web form to #{abuse_contact.name} for case #{report_case.case_number}")
      end

      success
    rescue ServiceError => e
      handle_error(e)
      false
    rescue StandardError => e
      handle_error(e)
      false
    end

    private

    def validate_submission!
      raise ArgumentError, "Submission is nil" unless submission
      raise ArgumentError, "Not a web form contact" unless abuse_contact.contact_web_form?
      raise ArgumentError, "Web form URL is blank" if abuse_contact.web_form_url.blank?
      raise ArgumentError, "Submission not in valid state" unless submission.status_pending? || submission.status_queued?
    end

    def report_case
      @report_case ||= submission.case
    end

    def abuse_contact
      @abuse_contact ||= submission.abuse_contact
    end

    def payload
      @payload ||= submission.payload || submission.build_payload
    end

    def determine_handler
      # Check for specific handler in web_form_fields
      handler_name = abuse_contact.web_form_fields&.dig("handler")&.to_s&.downcase
      return FORM_HANDLERS[handler_name] if handler_name.present? && FORM_HANDLERS.key?(handler_name)

      # Try to detect from name
      name = abuse_contact.name.downcase
      FORM_HANDLERS.each do |key, handler|
        return handler if name.include?(key)
      end

      # No handler found - will be skipped
      nil
    end

    # =========================================
    # Browser Automation Helpers
    # =========================================

    def with_browser
      require "ferrum"

      browser = Ferrum::Browser.new(
        headless: true,
        timeout: 30,
        window_size: [ 1280, 800 ]
      )

      begin
        yield browser
      ensure
        browser.quit
      end
    rescue LoadError
      log_error("Ferrum not available", StandardError.new("gem not installed"))
      raise ServiceError, "Browser automation not available"
    end

    # =========================================
    # Cloudflare Abuse Form
    # https://abuse.cloudflare.com/
    # =========================================
    def submit_cloudflare
      with_browser do |browser|
        browser.goto(abuse_contact.web_form_url)

        # Wait for form to load
        browser.network.wait_for_idle

        # Fill the form
        browser.at_css('input[name="urls"]')&.focus&.type(url_to_report)
        browser.at_css('input[name="email"]')&.focus&.type(report_case.email_address)
        browser.at_css('textarea[name="justification"]')&.focus&.type(build_report_text)

        # Select phishing category if available
        category_select = browser.at_css('select[name="abuse_type"]')
        category_select&.select("phishing") if category_select

        # Submit
        browser.at_css('button[type="submit"]')&.click

        # Wait for submission
        browser.network.wait_for_idle(timeout: 10)

        # Check for success
        success = browser.body.include?("Thank you") || browser.body.include?("submitted")

        submission.record_response!(
          status_code: success ? 200 : 400,
          body: "Web form submitted via browser automation"
        )

        success
      end
    end

    # =========================================
    # GoDaddy Abuse Form
    # https://supportcenter.godaddy.com/AbuseReport
    # =========================================
    def submit_godaddy
      with_browser do |browser|
        browser.goto(abuse_contact.web_form_url)
        browser.network.wait_for_idle

        # GoDaddy has a multi-step form
        # Step 1: Select abuse type
        browser.at_css('input[value="phishing"]')&.click
        browser.at_css('button[data-testid="continue"]')&.click
        browser.network.wait_for_idle(timeout: 5)

        # Step 2: Fill details
        browser.at_css('input[name="domain"]')&.focus&.type(payload[:domain])
        browser.at_css('input[name="url"]')&.focus&.type(url_to_report)
        browser.at_css('input[name="email"]')&.focus&.type(report_case.email_address)
        browser.at_css('textarea[name="details"]')&.focus&.type(build_report_text)

        # Submit
        browser.at_css('button[type="submit"]')&.click
        browser.network.wait_for_idle(timeout: 10)

        success = browser.body.include?("Thank you") || browser.body.include?("received")

        submission.record_response!(
          status_code: success ? 200 : 400,
          body: "Web form submitted via browser automation"
        )

        success
      end
    end

    # =========================================
    # Porkbun Abuse Form
    # https://porkbun.com/abuse
    # =========================================
    def submit_porkbun
      with_browser do |browser|
        browser.goto(abuse_contact.web_form_url)
        browser.network.wait_for_idle

        browser.at_css('input[name="domain"]')&.focus&.type(payload[:domain])
        browser.at_css('input[name="email"]')&.focus&.type(report_case.email_address)
        browser.at_css('select[name="type"]')&.select("phishing")
        browser.at_css('textarea[name="message"]')&.focus&.type(build_report_text)

        browser.at_css('button[type="submit"]')&.click
        browser.network.wait_for_idle(timeout: 10)

        success = browser.body.include?("Thank you") || browser.body.include?("submitted")

        submission.record_response!(
          status_code: success ? 200 : 400,
          body: "Web form submitted via browser automation"
        )

        success
      end
    end

    # =========================================
    # NameSilo Phishing Report Form
    # https://new.namesilo.com/phishing_report.php
    # =========================================
    def submit_namesilo
      with_browser do |browser|
        browser.goto(abuse_contact.web_form_url)
        browser.network.wait_for_idle

        browser.at_css('input[name="domain"]')&.focus&.type(payload[:domain])
        browser.at_css('input[name="url"]')&.focus&.type(url_to_report)
        browser.at_css('input[name="email"]')&.focus&.type(report_case.email_address)
        browser.at_css('textarea[name="comments"]')&.focus&.type(build_report_text)

        browser.at_css('button[type="submit"], input[type="submit"]')&.click
        browser.network.wait_for_idle(timeout: 10)

        success = browser.body.include?("Thank you") || browser.body.include?("submitted")

        submission.record_response!(
          status_code: success ? 200 : 400,
          body: "Web form submitted via browser automation"
        )

        success
      end
    end

    # =========================================
    # Hostinger Abuse Form
    # https://www.hostinger.com/report-abuse
    # =========================================
    def submit_hostinger
      with_browser do |browser|
        browser.goto(abuse_contact.web_form_url)
        browser.network.wait_for_idle

        browser.at_css('input[name="domain"]')&.focus&.type(payload[:domain])
        browser.at_css('input[name="url"]')&.focus&.type(url_to_report)
        browser.at_css('input[name="email"]')&.focus&.type(report_case.email_address)
        browser.at_css('select[name="type"]')&.select("Phishing")
        browser.at_css('textarea[name="description"]')&.focus&.type(build_report_text)

        browser.at_css('button[type="submit"]')&.click
        browser.network.wait_for_idle(timeout: 10)

        success = browser.body.include?("Thank you") || browser.body.include?("received")

        submission.record_response!(
          status_code: success ? 200 : 400,
          body: "Web form submitted via browser automation"
        )

        success
      end
    end

    # =========================================
    # Vercel Abuse Form
    # https://vercel.com/abuse
    # =========================================
    def submit_vercel
      with_browser do |browser|
        browser.goto(abuse_contact.web_form_url)
        browser.network.wait_for_idle

        browser.at_css('input[name="url"]')&.focus&.type(url_to_report)
        browser.at_css('input[name="email"]')&.focus&.type(report_case.email_address)
        browser.at_css('select[name="category"]')&.select("Phishing")
        browser.at_css('textarea[name="description"]')&.focus&.type(build_report_text)

        browser.at_css('button[type="submit"]')&.click
        browser.network.wait_for_idle(timeout: 10)

        success = browser.body.include?("Thank you") || browser.body.include?("received")

        submission.record_response!(
          status_code: success ? 200 : 400,
          body: "Web form submitted via browser automation"
        )

        success
      end
    end

    # =========================================
    # Namecheap (placeholder - requires CAPTCHA solving)
    # =========================================
    def submit_namecheap
      log_info("Namecheap requires CAPTCHA - skipping automation")
      submission.skip!
      true
    end

    # =========================================
    # Helpers
    # =========================================

    def url_to_report
      payload[:url] || "https://#{payload[:domain]}"
    end

    def build_report_text
      <<~TEXT.strip
        [Automated Report from phish.directory]

        Phishing URL: #{url_to_report}
        Domain: #{payload[:domain]}
        Classification: #{payload[:classification] || 'phishing'}
        Confidence: #{(payload[:confidence].to_f * 100).round}%
        Detection Sources: #{format_sources}
        Case Reference: #{payload[:case_reference]}

        This is an automated report generated by phish.directory, a collaborative phishing detection service.

        For questions or updates about this report, please contact:
        - Support: support@phish.directory
        - Case Email: #{report_case.email_address}

        Thank you for your prompt action in removing this malicious content.
      TEXT
    end

    def format_sources
      sources = payload[:sources]
      return "phish.directory aggregated intelligence" if sources.blank?

      sources.map { |s| s.is_a?(Hash) ? (s[:service] || s["service"]) : s.to_s }.join(", ")
    end

    def handle_error(error)
      log_error("Failed to submit web form", error)

      submission.record_attempt!(error: error.message)

      if submission.retryable?
        log_info("Submission will be retried (attempt #{submission.attempts}/#{submission.max_attempts})")
      else
        submission.fail!
        log_error("Submission failed permanently after #{submission.attempts} attempts", error)

        # Alert Jasper so he can manually submit and fix the automation
        send_failure_alert(error)
      end
    end

    def send_failure_alert(error)
      OpsMailer.with(
        contact: abuse_contact,
        submission: submission,
        error_message: error.message
      ).web_form_failure.deliver_later
    rescue StandardError => e
      log_error("Failed to send failure alert", e)
    end

    def log_error(message, error)
      logger.error("[WebFormSubmission] #{message}: #{error.message}")
    end

    def log_info(message)
      logger.info("[WebFormSubmission] #{message}")
    end
  end
end
