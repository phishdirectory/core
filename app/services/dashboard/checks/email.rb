# frozen_string_literal: true

module Dashboard
  module Checks
    class Email < Base
      FORMAT = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/

      def heading = "Check Email"
      def subheading = "Analyze email addresses for fraud and abuse"
      def placeholder = "someone@example.com"
      def empty_hint = "We check reputation, deliverability and whether the address is disposable."
      def submit_path_helper = :dashboard_check_email_path
      def api_path = "/api/v1/email/check"
      def field_label = "Email address"

      def normalize(input) = input.to_s.strip.downcase

      def valid?(value) = value.present? && value.match?(FORMAT)

      def invalid_message = "That does not look like a valid email address."

      def find_or_create(value) = Phish::Email.find_or_create_by_natural_key!(email: value)

      def run(record) = VerdictService.check_email!(record)

      def details(record)
        [
          { label: "Domain", value: record.domain.presence || "Unknown" },
          { label: "Reputation", value: record.reputation_score&.to_s || "Unknown" },
          { label: "Disposable", **yes_no(record.disposable) },
          # A free provider is neither good nor bad, so it gets a neutral tone
          # rather than being coloured like a risk signal.
          { label: "Free provider", **yes_no(record.free_provider, yes_tone: :neutral, no_tone: :neutral) },
          { label: "Deliverable", **yes_no(record.deliverable, yes_tone: :success, no_tone: :warning) },
          { label: "Valid MX", **yes_no(record.valid_mx, yes_tone: :success, no_tone: :warning) }
        ]
      end
    end
  end
end
