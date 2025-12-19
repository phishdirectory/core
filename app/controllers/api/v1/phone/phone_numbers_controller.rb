# frozen_string_literal: true

module Api
  module V1
    module Phone
      class PhoneNumbersController < BaseController
        # GET/POST /api/v1/phone/check
        def check
          phone = params[:phone]&.strip

          if phone.blank?
            return render json: { error: "Missing required parameter: phone" }, status: :bad_request
          end

          # Normalize phone number to E.164 format
          normalized_phone = normalize_phone(phone)

          # Validate phone format before database access
          unless valid_phone?(normalized_phone)
            return render json: { error: "Invalid phone number format. Expected E.164 format (e.g., +14155551234)" }, status: :bad_request
          end

          # Find or create the phone number record (create_or_find_by handles race conditions)
          phone_number = Phish::PhoneNumber.create_or_find_by!(phone_number: normalized_phone)

          # Track that this phone number was queried
          phone_number.touch_last_seen!

          # Check if we need to refresh the verdict
          if phone_number.needs_recheck?
            # Queue background check (future implementation)
            # PhishPhoneNumberCheckJob.perform_later(phone_number.id)
          end

          render json: serialize_phone_number(phone_number)
        end

        # GET/POST /api/v1/phone/bulk
        def bulk
          phones = Array(params[:phones]).map { |p| p&.strip }.compact.uniq

          if phones.empty?
            return render json: { error: "Missing required parameter: phones" }, status: :bad_request
          end

          if phones.size > 100
            return render json: { error: "Maximum 100 phone numbers per request" }, status: :bad_request
          end

          # Normalize all phone numbers first
          normalized_phones = phones.map { |p| normalize_phone(p) }

          # Validate all phone numbers before database access
          invalid_phones = phones.zip(normalized_phones).reject { |_, n| valid_phone?(n) }.map(&:first)
          if invalid_phones.any?
            return render json: {
              error: "Invalid phone number format. Expected E.164 format (e.g., +14155551234)",
              invalid_phones: invalid_phones.first(10)
            }, status: :bad_request
          end

          # Find existing phone numbers
          existing = Phish::PhoneNumber.where(phone_number: normalized_phones).index_by(&:phone_number)

          # Create missing phone numbers (create_or_find_by! handles race conditions)
          missing_phones = normalized_phones - existing.keys
          missing_phones.each do |phone|
            existing[phone] = Phish::PhoneNumber.create_or_find_by!(phone_number: phone)
          end

          # Update last_seen_at for all phone numbers in bulk
          Phish::PhoneNumber.where(phone_number: normalized_phones).update_all(last_seen_at: Time.current)

          # Reload all phone numbers with verdict and carrier eager loading to avoid N+1
          phone_numbers = Phish::PhoneNumber.includes(:verdict, :carrier)
                                            .where(phone_number: normalized_phones)
                                            .index_by(&:phone_number)

          # Serialize in original order
          results = normalized_phones.map { |p| serialize_phone_number(phone_numbers[p]) }

          render json: {
            results: results,
            count: results.size
          }
        end

        private

        def serialize_phone_number(phone_number)
          verdict = phone_number.verdict
          {
            id: phone_number.public_id,
            phone_number: phone_number.phone_number,
            verdict: verdict&.classification || "unknown",
            confidence: verdict&.confidence_score,
            phone_type: phone_number.phone_type,
            country_code: phone_number.country_code,
            carrier: phone_number.carrier&.name,
            scam_category: phone_number.scam_category,
            scam_subcategory: phone_number.scam_subcategory,
            verdict_id: verdict&.public_id,
            last_checked: phone_number.last_checked_at&.iso8601,
            created_at: phone_number.created_at.iso8601
          }
        end

        def normalize_phone(phone)
          # Use Phonelib to parse and normalize to E.164
          parsed = Phonelib.parse(phone)
          parsed.e164.presence || phone.gsub(/\s/, "")
        end

        # Validates E.164 format: +[country code][subscriber number]
        # Length: 1-15 digits after the +
        def valid_phone?(phone)
          phone.present? && phone.match?(/\A\+[1-9]\d{1,14}\z/)
        end
      end
    end
  end
end
