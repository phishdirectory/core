# frozen_string_literal: true

module Report
  # Handles inbound emails for report cases
  #
  # Emails sent to case_xxx@cases.phish.directory are routed here by
  # ApplicationMailbox. This mailbox:
  #   1. Finds the case by case_number from the To address
  #   2. Creates a CaseEmail record with the email content
  #   3. Attempts to match the sender to an existing submission
  #   4. Checks for acknowledgment/resolution patterns and updates status
  #
  # See docs/inbound_email_setup.md for configuration details.
  #
  class CasesMailbox < ApplicationMailbox
    before_processing :find_case

    def process
      Rails.logger.info("[Report::CasesMailbox] Processing email for case #{@report_case.case_number} from #{mail.from&.first}")

      # Create the case email record
      case_email = Report::CaseEmail.create_from_inbound!(
        case_record: @report_case,
        submission: find_related_submission,
        inbound_email: inbound_email
      )

      # Update case activity
      @report_case.update_activity!

      # Check for acknowledgment patterns
      check_for_acknowledgment(case_email)

      # Check for resolution patterns
      check_for_resolution(case_email)

      # Check for Cloudflare response with real hosting provider
      check_for_cloudflare_hosting_info(case_email)

      Rails.logger.info("[Report::CasesMailbox] Recorded email #{case_email.public_id} for case #{@report_case.case_number}")
    end

    private

    def find_case
      # Extract case number from the recipient address
      case_address = mail.to&.find { |addr| addr.match?(/^case_[a-z0-9]+@/i) }

      unless case_address
        Rails.logger.warn("[Report::CasesMailbox] No case address found in recipients: #{mail.to}")
        bounced!
        return
      end

      case_number = case_address.split("@").first

      @report_case = Report::Case.find_by_flake_id(case_number)

      unless @report_case
        Rails.logger.warn("[Report::CasesMailbox] Case not found: #{case_number}")
        bounced!
      end
    end

    def find_related_submission
      # Try to find the submission this email is replying to
      # Match by sender email to abuse contact
      sender = mail.from&.first&.downcase

      return nil if sender.blank?

      # Find submission where the abuse contact email matches sender
      @report_case.submissions.joins(:abuse_contact).find_by(
        "LOWER(report_abuse_contacts.email) = ?", sender
      )
    end

    def check_for_acknowledgment(case_email)
      # Look for common acknowledgment patterns in subject/body
      text = [ case_email.subject, case_email.body_text ].compact.join(" ").downcase

      acknowledgment_patterns = [
        /received/i,
        /ticket.*created/i,
        /case.*opened/i,
        /thank.*for.*report/i,
        /investigating/i,
        /looking.*into/i,
        /will.*review/i
      ]

      if acknowledgment_patterns.any? { |p| text.match?(p) }
        submission = case_email.submission || find_related_submission

        if submission&.status_sent? && submission.may_acknowledge?
          submission.acknowledge!

          Rails.logger.info("[Report::CasesMailbox] Submission #{submission.public_id} acknowledged based on email content")
        end
      end
    end

    def check_for_resolution(case_email)
      # Look for common resolution patterns
      text = [ case_email.subject, case_email.body_text ].compact.join(" ").downcase

      resolution_patterns = [
        /suspended/i,
        /terminated/i,
        /removed/i,
        /taken.*down/i,
        /action.*taken/i,
        /resolved/i,
        /domain.*deleted/i
      ]

      if resolution_patterns.any? { |p| text.match?(p) }
        submission = case_email.submission || find_related_submission

        if submission && (submission.status_sent? || submission.status_acknowledged?)
          if submission.may_mark_resolved?
            submission.mark_resolved!
            Rails.logger.info("[Report::CasesMailbox] Submission #{submission.public_id} resolved based on email content")
          end
        end
      end
    end

    # Check for Cloudflare responses that reveal the real hosting provider
    def check_for_cloudflare_hosting_info(case_email)
      hosting_info = case_email.extract_hosting_info
      return unless hosting_info

      Rails.logger.info(
        "[Report::CasesMailbox] Cloudflare revealed hosting info for case #{@report_case.case_number}: " \
        "#{hosting_info[:hosting_provider]} (#{hosting_info[:abuse_email]})"
      )

      # Find or create abuse contact for the hosting provider
      contact = find_or_create_hosting_contact(hosting_info)
      return unless contact

      # Check if we already have a submission to this contact
      existing = @report_case.submissions.find_by(abuse_contact: contact)
      if existing
        Rails.logger.info(
          "[Report::CasesMailbox] Already have submission to #{contact.name} for case #{@report_case.case_number}"
        )
        return
      end

      # Create new submission to the real hosting provider
      create_hosting_submission(contact, hosting_info)
    end

    def find_or_create_hosting_contact(hosting_info)
      email = hosting_info[:abuse_email]
      provider_name = hosting_info[:hosting_provider].presence || email_to_provider_name(email)

      # Try to find existing contact by email
      contact = Report::AbuseContact.find_by(email: email)
      return contact if contact

      # Create new hosting provider contact
      Report::AbuseContact.create!(
        name: provider_name,
        contact_type: :hosting,
        method: :email,
        email: email,
        priority: 5, # High priority for direct hosting providers
        active: true,
        notes: "Auto-discovered from Cloudflare response on #{Time.current.strftime('%Y-%m-%d')}"
      )
    rescue ActiveRecord::RecordInvalid => e
      Rails.logger.error("[Report::CasesMailbox] Failed to create hosting contact: #{e.message}")
      nil
    end

    def email_to_provider_name(email)
      # Convert abuse@example.com to "Example" as a fallback name
      domain = email.split("@").last
      domain.split(".").first.titleize
    end

    def create_hosting_submission(contact, hosting_info)
      # Build payload similar to original case creation
      payload = {
        domain: @report_case.domain_name,
        url: @report_case.url_value,
        classification: @report_case.verdict_snapshot&.classification,
        confidence: @report_case.confidence_at_creation,
        sources: @report_case.verdict_snapshot&.sources,
        detected_at: @report_case.created_at&.iso8601,
        case_reference: @report_case.case_number,
        reporter: "phish.directory",
        reporter_email: @report_case.email_address,
        discovered_ip: hosting_info[:ip_address],
        discovered_via: "Cloudflare abuse response"
      }.compact

      submission = @report_case.submissions.create!(
        abuse_contact: contact,
        payload: payload
      )

      Rails.logger.info(
        "[Report::CasesMailbox] Created submission #{submission.public_id} to #{contact.name} " \
        "for case #{@report_case.case_number}"
      )

      # Queue for processing
      Report::ProcessCaseJob.perform_later(@report_case.id)
    end
  end
end
