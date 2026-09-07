# frozen_string_literal: true

module Dashboard
  module Checks
    # One kind of thing a person can look up from the dashboard.
    #
    # The domain, email and phone pages were three near-identical copies that
    # had already drifted apart: the same `verdict == "phishing"` branch
    # rendered as "Phishing", "Fraudulent" and "Scam/Fraud" depending on which
    # copy you were looking at. Everything type-specific now lives in a
    # subclass and the page itself is shared.
    class Base
      class CheckFailed < StandardError; end

      TYPES = %w[domain url email phone].freeze

      # Resolved through an explicit map rather than const_get: this class
      # lives under Dashboard::Checks, but constant lookup walks up to Object,
      # where "Domain" is the unrelated Domain::AvailabilityService namespace.
      def self.for(key)
        klass = {
          "domain" => Checks::Domain,
          "url" => Checks::Url,
          "email" => Checks::Email,
          "phone" => Checks::Phone
        }[key.to_s]

        raise ArgumentError, "Unknown check type: #{key}" unless klass

        klass.new
      end

      # Identity ------------------------------------------------------------

      def key = self.class.name.demodulize.underscore
      def param = key.to_sym

      # Presentation --------------------------------------------------------

      def heading = raise(NotImplementedError)
      def subheading = raise(NotImplementedError)
      def placeholder = raise(NotImplementedError)
      def field_label = heading.sub(/\ACheck /, "")
      def submit_label = heading
      def empty_hint = raise(NotImplementedError)
      def api_path = raise(NotImplementedError)
      def api_field = param.to_s

      # Named explicitly rather than derived with url_for, which would carry
      # the route's `type` default through as a query string.
      def submit_path_helper = raise(NotImplementedError)

      # Behaviour -----------------------------------------------------------

      # Returns the value we will actually look up. Subclasses that discard
      # part of the input must say so through normalization_note.
      def normalize(input) = input.to_s.strip

      def valid?(_value) = raise(NotImplementedError)

      def invalid_message = "That does not look like a valid #{field_label.downcase}."

      # Explains what we changed about the input, or nil when we changed
      # nothing. Silently checking something other than what was typed is how
      # a pasted link turned into a bare domain with no indication.
      def normalization_note(_original, _normalized) = nil

      def find_or_create(_value) = raise(NotImplementedError)

      def run(_record) = raise(NotImplementedError)

      # Extra fields for this type, as [{ label:, value:, tone: }].
      def details(_record) = []

      protected

      def yes_no(value, yes_tone: :warning, no_tone: :success)
        return { value: "Unknown", tone: :neutral } if value.nil?

        value ? { value: "Yes", tone: yes_tone } : { value: "No", tone: no_tone }
      end
    end
  end
end
