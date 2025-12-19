# frozen_string_literal: true

module Dashboard
  class EmailChecksController < BaseController
    def new
      @email = nil
      @result = nil
    end

    def create
      email = params[:email]&.strip&.downcase

      if email.blank?
        flash.now[:alert] = "Please enter an email address to check"
        return render :new
      end

      @email = email

      unless valid_email?(@email)
        flash.now[:alert] = "Invalid email format. Please enter a valid email address."
        return render :new
      end

      # Find or create the email record
      phish_email = Phish::Email.find_or_create_by(email: @email)

      # Run the check if needed (stale or never checked)
      if phish_email.needs_check?
        run_email_check(phish_email)
        phish_email.reload
      end

      # Build result
      @result = {
        email: @email,
        domain: phish_email.domain,
        verdict: phish_email.classification || "unknown",
        confidence: phish_email.confidence_score,
        disposable: phish_email.disposable,
        free_provider: phish_email.free_provider,
        deliverable: phish_email.deliverable,
        valid_mx: phish_email.valid_mx,
        reputation_score: phish_email.reputation_score,
        sources: phish_email.verdict&.sources_list || [],
        last_checked: phish_email.last_checked_at,
        created_at: phish_email.created_at
      }

      render :new
    end

    private

    def run_email_check(phish_email)
      VerdictService.check_email!(phish_email)
    rescue StandardError => e
      Rails.logger.error("[EmailCheck] Failed to check #{phish_email.email}: #{e.message}")
      # Don't fail the request, just show unknown
    end

    def valid_email?(email)
      email.present? && email.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
    end
  end
end
