# frozen_string_literal: true

module Api
  module V1
    module Email
      class EmailsController < BaseController
        # GET/POST /api/v1/email/check
        def check
          email = params[:email]&.strip&.downcase

          if email.blank?
            return render json: { error: "Missing required parameter: email" }, status: :bad_request
          end

          # Validate email format before database access
          unless valid_email?(email)
            return render json: { error: "Invalid email format" }, status: :bad_request
          end

          # Find or create the email record (create_or_find_by handles race conditions)
          phish_email = Phish::Email.create_or_find_by!(email: email)

          # Track that this email was queried
          phish_email.touch_last_seen!

          # Check if we need to refresh the verdict
          if phish_email.needs_recheck?
            # Queue background check (future implementation)
            # PhishEmailCheckJob.perform_later(phish_email.id)
          end

          render json: serialize_email(phish_email)
        end

        # GET/POST /api/v1/email/bulk
        def bulk
          emails = Array(params[:emails]).map { |e| e&.strip&.downcase }.compact.uniq

          if emails.empty?
            return render json: { error: "Missing required parameter: emails" }, status: :bad_request
          end

          if emails.size > 100
            return render json: { error: "Maximum 100 emails per request" }, status: :bad_request
          end

          # Validate all emails before database access
          invalid_emails = emails.reject { |e| valid_email?(e) }
          if invalid_emails.any?
            return render json: {
              error: "Invalid email format",
              invalid_emails: invalid_emails.first(10)
            }, status: :bad_request
          end

          # Find existing emails
          existing = Phish::Email.where(email: emails).index_by(&:email)

          # Create missing emails (create_or_find_by! handles race conditions)
          missing_emails = emails - existing.keys
          missing_emails.each do |email|
            existing[email] = Phish::Email.create_or_find_by!(email: email)
          end

          # Update last_seen_at for all emails in bulk
          Phish::Email.where(email: emails).update_all(last_seen_at: Time.current)

          # Reload all emails with verdict eager loading to avoid N+1
          phish_emails = Phish::Email.includes(:verdict).where(email: emails).index_by(&:email)

          # Serialize in original order
          results = emails.map { |e| serialize_email(phish_emails[e]) }

          render json: {
            results: results,
            count: results.size
          }
        end

        private

        def serialize_email(phish_email)
          verdict = phish_email.verdict
          {
            id: phish_email.public_id,
            email: phish_email.email,
            domain: phish_email.domain,
            verdict: verdict&.classification || "unknown",
            confidence: verdict&.confidence_score,
            disposable: phish_email.disposable,
            free_provider: phish_email.free_provider,
            deliverable: phish_email.deliverable,
            valid_mx: phish_email.valid_mx,
            reputation_score: phish_email.reputation_score,
            scam_category: phish_email.scam_category,
            scam_subcategory: phish_email.scam_subcategory,
            verdict_id: verdict&.public_id,
            last_checked: phish_email.last_checked_at&.iso8601,
            created_at: phish_email.created_at.iso8601
          }
        end

        def valid_email?(email)
          email.present? && email.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
        end
      end
    end
  end
end
