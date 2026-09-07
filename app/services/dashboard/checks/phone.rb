# frozen_string_literal: true

module Dashboard
  module Checks
    class Phone < Base
      E164 = /\A\+[1-9]\d{1,14}\z/

      def heading = "Check Phone Number"
      def subheading = "Analyze phone numbers for scam and fraud activity"
      def placeholder = "+1 415 555 1234"
      def empty_hint = "We check the number against reputation data for scam and fraud reports."
      def submit_path_helper = :dashboard_check_phone_path
      def api_path = "/api/v1/phone/check"
      def field_label = "Phone number"
      def param = :phone

      def normalize(input)
        parsed = Phonelib.parse(input)
        parsed.e164.presence || input.to_s.gsub(/[^\d+]/, "")
      end

      def valid?(value) = value.present? && value.match?(E164)

      def invalid_message = "Enter a phone number in international format, for example +14155551234."

      def normalization_note(original, normalized)
        return nil if original.to_s.strip == normalized

        "Checked #{normalized}, the international form of what you entered."
      end

      def find_or_create(value) = Phish::PhoneNumber.find_or_create_by_natural_key!(phone_number: value)

      def run(record) = VerdictService.check_phone!(record)

      def details(record)
        [
          { label: "Type", value: record.phone_type.presence&.titleize || "Unknown" },
          { label: "Country", value: record.country_code.presence || "Unknown" },
          { label: "Carrier", value: record.carrier&.name.presence || "Unknown" }
        ]
      end
    end
  end
end
