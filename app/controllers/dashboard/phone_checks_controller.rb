# frozen_string_literal: true

module Dashboard
  class PhoneChecksController < BaseController
    def new
      @phone = nil
      @result = nil
    end

    def create
      phone = params[:phone]&.strip

      if phone.blank?
        flash.now[:alert] = "Please enter a phone number to check"
        return render :new
      end

      # Normalize phone number to E.164 format
      @phone = normalize_phone(phone)

      unless valid_phone?(@phone)
        flash.now[:alert] = "Invalid phone number format. Please enter a valid phone number."
        return render :new
      end

      # Find or create the phone number record
      phish_phone = Phish::PhoneNumber.find_or_create_by(phone_number: @phone)

      # Run the check if needed (stale or never checked)
      if phish_phone.needs_check?
        run_phone_check(phish_phone)
        phish_phone.reload
      end

      # Build result
      @result = {
        phone_number: @phone,
        verdict: phish_phone.classification || "unknown",
        confidence: phish_phone.confidence_score,
        phone_type: phish_phone.phone_type,
        country_code: phish_phone.country_code,
        carrier: phish_phone.carrier&.name,
        sources: phish_phone.verdict&.sources_list || [],
        last_checked: phish_phone.last_checked_at,
        created_at: phish_phone.created_at
      }

      render :new
    end

    private

    def run_phone_check(phish_phone)
      VerdictService.check_phone!(phish_phone)
    rescue StandardError => e
      Rails.logger.error("[PhoneCheck] Failed to check #{phish_phone.phone_number}: #{e.message}")
      # Don't fail the request, just show unknown
    end

    def normalize_phone(phone)
      # Use Phonelib for proper E.164 normalization
      parsed = Phonelib.parse(phone)
      parsed.e164.presence || phone.gsub(/[^\d+]/, "")
    end

    def valid_phone?(phone)
      phone.present? && phone.match?(/\A\+[1-9]\d{1,14}\z/)
    end
  end
end
