# frozen_string_literal: true

require "whois"
require "whois/parser"
require "rdap"

module Phish
  # Service for looking up domain registration information via RDAP and WHOIS
  #
  # Uses RDAP as primary source (newer, more structured protocol)
  # Falls back to WHOIS if RDAP fails
  # Caches results in database and Rails.cache for performance
  #
  # Usage:
  #   service = Phish::DomainExpiryService.new
  #   result = service.lookup("example.com")
  #   # => { domain: "example.com", registrar: "...", expires_at: ..., ... }
  #
  class DomainExpiryService < BaseService
    include RateLimitable

    # Rate limits for external WHOIS/RDAP servers
    # RDAP bootstrap servers have moderate limits
    # WHOIS servers have stricter per-TLD limits
    rate_limit :minute, requests: 60, period: 1.minute
    rate_limit :daily, requests: 5000, period: 1.day

    CACHE_TTL = 24.hours

    class LookupError < ServiceError; end
    class DomainNotFoundError < LookupError; end

    # Main entry point for domain registration lookup
    #
    # @param domain [String] Domain to look up
    # @param force [Boolean] Skip cache and force fresh lookup
    # @return [Hash] Registration information
    #
    def lookup(domain)
      normalized = normalize_domain(domain)

      # Check Rails.cache first (fast)
      cached = read_cache(normalized)
      return cached if cached

      # Check database (slower but persistent)
      db_record = DomainRegistration.find_fresh(normalized)
      if db_record
        write_cache(normalized, serialize_record(db_record))
        return serialize_record(db_record)
      end

      # Perform fresh lookup
      with_rate_limit do
        result = perform_lookup(normalized)
        save_result(normalized, result)
        result
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("Domain expiry lookup rate limited", retry_after: e.retry_after)
    end

    # Force fresh lookup, bypassing cache
    #
    # @param domain [String] Domain to look up
    # @return [Hash] Registration information
    #
    def lookup!(domain)
      normalized = normalize_domain(domain)

      with_rate_limit do
        result = perform_lookup(normalized)
        save_result(normalized, result)
        result
      end
    rescue RateLimitable::RateLimitExceeded => e
      raise RateLimitError.new("Domain expiry lookup rate limited", retry_after: e.retry_after)
    end

    # Batch lookup for multiple domains
    #
    # @param domains [Array<String>] Domains to look up
    # @return [Hash] Results keyed by domain
    #
    def bulk_lookup(domains)
      results = {}
      errors = []

      domains.each do |domain|
        results[domain] = lookup(domain)
      rescue LookupError => e
        errors << { domain: domain, error: e.message }
      rescue RateLimitError => e
        errors << { domain: domain, error: "Rate limited", retry_after: e.retry_after }
        break # Stop processing on rate limit
      end

      { results: results, errors: errors }
    end

    private

    # Perform the actual lookup using RDAP then WHOIS fallback
    def perform_lookup(domain)
      # Try RDAP first (newer, more structured)
      result = rdap_lookup(domain)
      return result if result

      # Fall back to WHOIS
      result = whois_lookup(domain)
      return result if result

      # Neither worked
      raise DomainNotFoundError, "Could not find registration info for #{domain}"
    end

    # RDAP lookup using rdap gem
    def rdap_lookup(domain)
      log_info("Attempting RDAP lookup for #{domain}")

      response = Rdap.domain(domain)
      return nil unless response

      parse_rdap_response(domain, response)
    rescue Rdap::NotFound
      log_info("RDAP: Domain not found for #{domain}")
      nil
    rescue Rdap::Error => e
      log_error("RDAP lookup failed", e)
      nil
    rescue StandardError => e
      log_error("RDAP unexpected error", e)
      nil
    end

    # WHOIS lookup using whois/whois-parser gems
    def whois_lookup(domain)
      log_info("Attempting WHOIS lookup for #{domain}")

      client = Whois::Client.new
      record = client.lookup(domain)
      return nil unless record

      parser = record.parser
      return nil unless parser

      parse_whois_response(domain, parser, record)
    rescue Whois::ServerNotFound
      log_info("WHOIS: No server found for #{domain}")
      nil
    rescue Whois::Error => e
      log_error("WHOIS lookup failed", e)
      nil
    rescue Whois::Parser::ParserError => e
      log_error("WHOIS parser error", e)
      nil
    rescue StandardError => e
      log_error("WHOIS unexpected error", e)
      nil
    end

    # Parse RDAP response into standardized format
    def parse_rdap_response(domain, response)
      # Extract registrar from entities
      registrar = nil
      registrar_url = nil

      if response.respond_to?(:entities) && response.entities.present?
        registrar_entity = response.entities.find { |e| e.roles&.include?("registrar") }
        if registrar_entity
          registrar = registrar_entity.fn || registrar_entity.handle
          registrar_url = registrar_entity.url
        end
      end

      # Extract dates from events
      created_at = nil
      updated_at = nil
      expires_at = nil

      if response.respond_to?(:events) && response.events.present?
        response.events.each do |event|
          case event.action
          when "registration"
            created_at = parse_datetime(event.date)
          when "last changed", "last update of RDAP database"
            updated_at = parse_datetime(event.date)
          when "expiration"
            expires_at = parse_datetime(event.date)
          end
        end
      end

      # Extract nameservers
      nameservers = []
      if response.respond_to?(:nameservers) && response.nameservers.present?
        nameservers = response.nameservers.map { |ns| ns.respond_to?(:name) ? ns.name : ns.to_s }.compact
      end

      # Extract status
      status = []
      if response.respond_to?(:status) && response.status.present?
        status = Array(response.status)
      end

      # Check DNSSEC
      dnssec = false
      if response.respond_to?(:secure_dns)
        dnssec = response.secure_dns&.delegation_signed || false
      end

      build_lookup_result(
        domain: domain,
        registrar: registrar,
        registrar_url: registrar_url,
        registered_at: created_at,
        updated_at: updated_at,
        expires_at: expires_at,
        nameservers: nameservers,
        status: status,
        dnssec: dnssec,
        source: "rdap",
        raw_data: response.to_h
      )
    end

    # Parse WHOIS response into standardized format
    def parse_whois_response(domain, parser, record)
      build_lookup_result(
        domain: domain,
        registrar: safe_call(parser, :registrar)&.name,
        registrar_url: safe_call(parser, :registrar)&.url,
        registered_at: safe_call(parser, :created_on),
        updated_at: safe_call(parser, :updated_on),
        expires_at: safe_call(parser, :expires_on),
        nameservers: Array(safe_call(parser, :nameservers)).map { |ns| ns.respond_to?(:name) ? ns.name : ns.to_s },
        status: Array(safe_call(parser, :status)),
        dnssec: safe_call(parser, :dnssec) || false,
        source: "whois",
        raw_data: { content: record.content&.first(10000) } # Truncate raw WHOIS
      )
    end

    # Build standardized result hash
    def build_lookup_result(domain:, registrar:, registrar_url:, registered_at:, updated_at:, expires_at:,
                            nameservers:, status:, dnssec:, source:, raw_data:)
      registered_at = parse_datetime(registered_at)
      updated_at = parse_datetime(updated_at)
      expires_at = parse_datetime(expires_at)

      {
        domain: domain,
        registrar: registrar,
        registrar_url: registrar_url,
        registered_at: registered_at&.iso8601,
        updated_at: updated_at&.iso8601,
        expires_at: expires_at&.iso8601,
        domain_age_days: registered_at ? ((Time.current - registered_at) / 1.day).to_i : nil,
        days_until_expiry: expires_at ? ((expires_at - Time.current) / 1.day).to_i : nil,
        nameservers: nameservers.compact.uniq,
        status: status.compact.uniq,
        dnssec: dnssec,
        source: source,
        queried_at: Time.current.iso8601
      }
    end

    # Save result to database and cache
    def save_result(domain, result)
      record = DomainRegistration.find_or_initialize_by(domain: domain)
      record.assign_attributes(
        registrar: result[:registrar],
        registrar_url: result[:registrar_url],
        registered_at: parse_datetime(result[:registered_at]),
        updated_at_registry: parse_datetime(result[:updated_at]),
        expires_at: parse_datetime(result[:expires_at]),
        nameservers: result[:nameservers],
        status: result[:status],
        dnssec: result[:dnssec],
        source: result[:source],
        raw_data: nil, # Don't store raw data to save space
        queried_at: Time.current
      )
      record.save!

      write_cache(domain, result)
      result
    rescue ActiveRecord::RecordInvalid => e
      log_error("Failed to save domain registration", e)
      result # Return result even if save fails
    end

    # Serialize database record to result hash
    def serialize_record(record)
      {
        domain: record.domain,
        registrar: record.registrar,
        registrar_url: record.registrar_url,
        registered_at: record.registered_at&.iso8601,
        updated_at: record.updated_at_registry&.iso8601,
        expires_at: record.expires_at&.iso8601,
        domain_age_days: record.domain_age_days,
        days_until_expiry: record.days_until_expiry,
        nameservers: record.nameservers,
        status: record.status,
        dnssec: record.dnssec,
        source: record.source,
        queried_at: record.queried_at.iso8601
      }
    end

    # Cache helpers
    def cache_key(domain)
      DomainRegistration.cache_key_for(domain)
    end

    def read_cache(domain)
      Rails.cache.read(cache_key(domain))
    end

    def write_cache(domain, result)
      Rails.cache.write(cache_key(domain), result, expires_in: CACHE_TTL)
    end

    # Safely call a method that might not exist or might raise
    def safe_call(object, method)
      return nil unless object.respond_to?(method)

      object.public_send(method)
    rescue StandardError
      nil
    end

    # Parse various datetime formats
    def parse_datetime(value)
      return nil if value.blank?
      return value if value.is_a?(Time) || value.is_a?(DateTime)

      Time.parse(value.to_s)
    rescue ArgumentError
      nil
    end
  end
end
