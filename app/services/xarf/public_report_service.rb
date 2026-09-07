# frozen_string_literal: true

module Xarf
  # Turns something a person pasted into a browser into an X-ARF report.
  #
  # The point raised against XARF is that it asks an ordinary reporter to
  # hand-write JSON, which gatekeeps who is able to report abuse at all. This
  # service is the answer to that: paste a link, get the JSON.
  #
  # It runs the same check the API runs and only emits a report when our own
  # sources agree the thing is malicious. A reporter cannot assert a verdict
  # here, so the reports that leave this page stay worth reading.
  class PublicReportService
    TYPES = %w[url domain].freeze
    DEFAULT_TYPE = "url"

    # What each outcome means, in the words the reporter reads. An outage and a
    # genuine "nobody has heard of this" answer must never collapse into one
    # message: that would tell someone their real phishing site is fine.
    MESSAGES = {
      blank: "Enter a link or a domain to report.",
      invalid: "That does not look like a link or a domain we can check.",
      lookup_failed: "We could not reach our threat intelligence sources just now. " \
                     "This is not a verdict on the link. Try again in a moment.",
      unknown: "We checked this and no source has anything on it yet. " \
               "We only generate reports for things we can back up with evidence.",
      clean: "We checked this and believe it is legitimate. " \
             "If you think that is wrong, contact abuse@phish.directory.",
      protected: "This is on our protected list and is never reported."
    }.freeze

    # The outcome of one attempt, including the outcomes that produce no
    # report. The page has to explain every one of them to the person who is
    # standing in front of it, so each gets its own status rather than a bare
    # nil.
    #
    # status is one of:
    #   :reportable     - we have a report
    #   :blank          - nothing was entered
    #   :invalid        - not a URL or domain we can parse
    #   :lookup_failed  - our sources could not be reached
    #   :unknown        - checked, but no source has anything on it
    #   :clean          - checked, and believed to be legitimate
    #   :protected      - on our protected list, never reportable
    Result = Struct.new(
      :status, :type, :value, :original, :note, :record, :verdict, :report,
      keyword_init: true
    ) do
      def reportable? = status == :reportable
      def message = MESSAGES.fetch(status, MESSAGES[:invalid])
      def classification = verdict&.classification
      def confidence = verdict&.confidence_score
      def sources = verdict&.sources_list || []
      def json = report && JSON.pretty_generate(report)

      # Filename a reporter can drop straight into an email attachment.
      def filename
        slug = value.to_s.gsub(%r{\Ahttps?://}, "").gsub(/[^a-z0-9.-]+/i, "-")
                    .delete_prefix("-").delete_suffix("-").first(60)
        "xarf-#{slug.presence || 'report'}.json"
      end
    end

    attr_reader :type, :input

    def self.call(...) = new(...).call

    def initialize(type:, input:)
      @type = TYPES.include?(type.to_s) ? type.to_s : DEFAULT_TYPE
      @input = input.to_s
    end

    def call
      return result(:blank) if input.strip.blank?

      value = check.normalize(input)
      return result(:invalid, value: value) unless check.valid?(value)

      record = check.find_or_create(value)

      # An outage and a genuine "nobody has heard of this" answer are different
      # facts. Saying "not reportable" for both would tell someone their real
      # phishing site is fine.
      return result(:lookup_failed, value: value, record: record) unless refresh(record)

      verdict = record.reload.verdict
      report = generate(record)

      result(
        report ? :reportable : status_without_report(verdict),
        value: value,
        record: record,
        verdict: verdict,
        report: report
      )
    end

    private

    # The dashboard already knows how to normalize, validate, find and check
    # each kind of input. Reusing it keeps one definition of what counts as a
    # valid URL; only the presentation methods on these classes are specific
    # to the dashboard, and this does not call them.
    def check = @check ||= Dashboard::Checks::Base.for(type)

    def result(status, **attrs)
      Result.new(
        status: status,
        type: type,
        original: input,
        note: attrs[:value] ? check.normalization_note(input, attrs[:value]) : nil,
        **attrs
      )
    end

    def refresh(record)
      return true unless record.needs_check?

      check.run(record)
      true
    rescue StandardError => e
      Rails.logger.error("[Xarf::PublicReport] #{type} #{record.id}: #{e.class} #{e.message}")
      false
    end

    def generate(record)
      generator = ReportGenerator.new

      report = case record
      when Phish::Url then generator.generate_for_url(record)
      when Phish::Domain then generator.generate_for_domain(record)
      end

      report && report[:error].nil? ? report : nil
    end

    def status_without_report(verdict)
      case verdict&.classification
      when "clean" then :clean
      when "protected" then :protected
      else :unknown
      end
    end
  end
end
