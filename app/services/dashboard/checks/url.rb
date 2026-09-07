# frozen_string_literal: true

module Dashboard
  module Checks
    # The homepage has always advertised URL verification and Phish::Url has
    # always existed, but there was no way to check one from the dashboard.
    class Url < Base
      def heading = "Check URL"
      def subheading = "Analyze full links, including the path"
      def placeholder = "https://example.com/login"
      def empty_hint = "Paste the whole link. The path and query are part of what gets checked."
      def submit_path_helper = :dashboard_check_url_path
      def api_path = "/api/v1/url/check"

      def normalize(input)
        value = input.to_s.strip
        value = "https://#{value}" unless value.match?(%r{\Ahttps?://}i)
        uri = URI.parse(value)
        uri.host = uri.host&.downcase
        uri.to_s
      rescue URI::InvalidURIError
        input.to_s.strip
      end

      def valid?(value)
        uri = URI.parse(value.to_s)
        uri.is_a?(URI::HTTP) && uri.host.present?
      rescue URI::InvalidURIError
        false
      end

      def invalid_message = "That does not look like a valid URL."

      def normalization_note(original, normalized)
        return nil if original.strip == normalized

        "Checked #{normalized}."
      end

      def find_or_create(value) = Phish::Url.find_or_create_by_natural_key!(url: value)

      def run(record) = VerdictService.check_url!(record)

      def details(record)
        [ { label: "Host", value: record.domain.presence || "Unknown" } ]
      end
    end
  end
end
