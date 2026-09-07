# frozen_string_literal: true

module Dashboard
  module Checks
    class Domain < Base
      FORMAT = /\A[a-z0-9]+([\-.]{1}[a-z0-9]+)*\.[a-z]{2,}\z/i

      def heading = "Check Domain"
      def subheading = "Analyze domains for phishing threats"
      def placeholder = "example.com"
      def empty_hint = "We check it against Google Safe Browsing, VirusTotal, URLScan and other threat intelligence sources."
      def submit_path_helper = :dashboard_check_path
      def api_path = "/api/v1/domain/check"

      def normalize(input)
        input.to_s.strip.downcase
             .sub(%r{\Ahttps?://}, "")
             .split("/").first.to_s
             .split("?").first.to_s
             .split(":").first.to_s
      end

      def valid?(value) = value.present? && value.match?(FORMAT)

      # Pasting a full link is the common case, and we quietly threw away
      # everything after the host without saying so.
      def normalization_note(original, normalized)
        return nil if original.strip.casecmp?(normalized)

        "Checked the domain #{normalized} from what you entered. " \
          "To check a full link instead, use the URL check."
      end

      def find_or_create(value) = Phish::Domain.find_or_create_by_natural_key!(domain: value)

      def run(record) = VerdictService.check_domain!(record)
    end
  end
end
