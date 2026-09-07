# frozen_string_literal: true

class VerdictService
  # Classifications that represent real knowledge about a record. An "unknown"
  # result must never replace one of these.
  MEANINGFUL_CLASSIFICATIONS = %w[phishing suspicious clean protected].freeze

  class << self
    # Updates or creates a verdict for a domain/URL record atomically.
    #
    # An "unknown" result means we learned nothing this run, which is very
    # different from learning that a record is clean. Every upstream failing at
    # once produces "unknown", so writing it over an existing verdict would let
    # a DNS blip or a batch of expired API keys quietly downgrade a confirmed
    # phishing domain. When that happens we keep the verdict we already have.
    #
    # @param record [Phish::Domain, Phish::Url] The domain or URL record
    # @param result [Hash] The aggregator service result with :verdict, :confidence, :details
    # @return [Verdict] The created/updated verdict
    def update_verdict!(record, result)
      if downgrade_to_unknown?(record, result)
        Rails.logger.warn(
          "[VerdictService] Keeping existing #{record.verdict.classification} verdict for " \
          "#{record.class.name}##{record.id}: this check returned unknown " \
          "(#{result.dig(:details, :reason) || "no reason given"})"
        )
        return record.verdict
      end

      ActiveRecord::Base.transaction do
        verdict = record.verdict || record.build_verdict
        verdict.assign_attributes(
          classification: result[:verdict],
          confidence_score: result[:confidence],
          sources: result[:details]&.dig(:service_results) || [],
          metadata: result[:details] || {}
        )
        verdict.save!

        record.update!(verdict: verdict, last_checked_at: Time.current)

        verdict
      end
    end

    # Records a verdict a trusted source supplied for a record.
    #
    # Nothing here came from Phish::AggregatorService, so there are no per-source
    # results to weigh against each other: the source is the only source, and its
    # classification stands. That is the whole point of marking a key trusted.
    #
    # The downgrade_to_unknown? guard does not apply. A trusted source may not
    # send "unknown" at all, so it can never overwrite real knowledge with the
    # absence of it.
    #
    # @param record [Phish::Domain, Phish::Url, Phish::Email, Phish::PhoneNumber]
    # @param classification [String] One of TrustedSourceUpsertService::CLASSIFICATIONS
    # @param confidence [Float] 0.0 to 1.0
    # @param source [String] Name of the submitting service
    # @param metadata [Hash] Extra context to store on the verdict
    # @return [Verdict] The created/updated verdict
    def apply_trusted_source!(record, classification:, confidence:, source:, metadata: {})
      submitted_at = Time.current

      ActiveRecord::Base.transaction do
        verdict = record.verdict || record.build_verdict
        verdict.assign_attributes(
          classification: classification,
          confidence_score: confidence,
          sources: [ { "name" => source, "result" => classification, "checked_at" => submitted_at.iso8601 } ],
          metadata: metadata.merge(
            "trusted_source" => source,
            "submitted_at" => submitted_at.iso8601,
            "reason" => "Trusted source submission"
          )
        )
        verdict.save!

        record.update!(verdict: verdict, last_checked_at: submitted_at)

        verdict
      end
    end

    # True when this result would replace real knowledge with "we don't know".
    def downgrade_to_unknown?(record, result)
      result[:verdict] == "unknown" &&
        MEANINGFUL_CLASSIFICATIONS.include?(record.verdict&.classification)
    end

    # Runs a phishing check on a domain and updates its verdict.
    #
    # @param domain [Phish::Domain] The domain record to check
    # @return [Hash] The aggregator service result
    def check_domain!(domain)
      service = Phish::AggregatorService.new
      result = service.check_domain(domain.domain)

      update_verdict!(domain, result)

      result
    end

    # Runs a phishing check on a URL and updates its verdict.
    #
    # @param url [Phish::Url] The URL record to check
    # @return [Hash] The aggregator service result
    def check_url!(url)
      service = Phish::AggregatorService.new
      result = service.check_url(url.url)

      update_verdict!(url, result)

      result
    end

    # Runs a fraud/reputation check on an email and updates its verdict.
    #
    # @param email [Phish::Email] The email record to check
    # @return [Hash] The email aggregator service result
    def check_email!(email)
      service = Phish::EmailAggregatorService.new
      result = service.check_email(email.email)

      update_email_verdict!(email, result)

      result
    end

    # Updates or creates a verdict for an email record atomically.
    #
    # @param email [Phish::Email] The email record
    # @param result [Hash] The aggregator service result with :verdict, :confidence, :details
    # @return [Verdict] The created/updated verdict
    def update_email_verdict!(email, result)
      ActiveRecord::Base.transaction do
        verdict = email.verdict || email.build_verdict
        verdict.assign_attributes(
          classification: result[:verdict],
          confidence_score: result[:confidence],
          sources: result[:details]&.dig(:sources) || [],
          metadata: result[:details] || {}
        )
        verdict.save!

        # Extract email-specific metadata from aggregator response
        metadata = result[:details]&.dig(:metadata) || {}
        email.update!(
          verdict: verdict,
          last_checked_at: Time.current,
          disposable: metadata[:disposable],
          free_provider: metadata[:free_provider],
          deliverable: metadata[:deliverable],
          valid_mx: metadata[:valid_mx],
          reputation_score: metadata[:reputation]
        )

        verdict
      end
    end

    # Runs a reputation check on a phone number and updates its verdict.
    #
    # @param phone_number [Phish::PhoneNumber] The phone number record to check
    # @return [Hash] The phone aggregator service result
    def check_phone!(phone_number)
      service = Phish::PhoneAggregatorService.new
      result = service.check_phone(phone_number.phone_number)

      update_phone_verdict!(phone_number, result)

      result
    end

    # Updates or creates a verdict for a phone number record atomically.
    #
    # @param phone_number [Phish::PhoneNumber] The phone number record
    # @param result [Hash] The aggregator service result with :verdict, :confidence, :details
    # @return [Verdict] The created/updated verdict
    def update_phone_verdict!(phone_number, result)
      ActiveRecord::Base.transaction do
        verdict = phone_number.verdict || phone_number.build_verdict
        verdict.assign_attributes(
          classification: result[:verdict],
          confidence_score: result[:confidence],
          sources: result[:details]&.dig(:sources) || [],
          metadata: result[:details] || {}
        )
        verdict.save!

        # Extract phone-specific metadata from aggregator response
        metadata = result[:details]&.dig(:metadata) || {}
        phone_number.update!(
          verdict: verdict,
          last_checked_at: Time.current,
          phone_type: metadata[:phone_type] || metadata[:line_type],
          country_code: metadata[:country_code]
        )

        verdict
      end
    end
  end
end
