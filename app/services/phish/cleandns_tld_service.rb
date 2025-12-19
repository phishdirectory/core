# frozen_string_literal: true

module Phish
  # Service to sync TLD support data from CleanDNS API
  # https://api.cleandns.dev/v2/abuse/clients
  #
  # The API returns groups of abuse clients, each containing:
  # - tlds: array of TLD names supported by this client group
  # - registrars: array of registrar names
  # - resellers: array of reseller names
  #
  class CleandnsTldService < BaseService
    BASE_URL = "https://api.cleandns.dev"

    # Conservative rate limits (be a good API citizen)
    rate_limit :minute, requests: 10, period: 1.minute
    rate_limit :daily, requests: 100, period: 1.day

    # Override since this service doesn't check domains/urls
    def check_domain(_domain)
      raise NotImplementedError, "#{service_name} does not check domains"
    end

    def check_url(_url)
      raise NotImplementedError, "#{service_name} does not check URLs"
    end

    # Sync all TLD support data from CleanDNS
    # Returns hash with :success, :created, :updated, :supported_tlds
    def sync
      log_info("Starting CleanDNS TLD sync...")

      with_rate_limit do
        response = fetch_abuse_clients
        return { success: false, error: "Failed to fetch data" } unless response

        process_response(response)
      end
    rescue RateLimitable::RateLimitExceeded => e
      log_error("Rate limit exceeded", e)
      { success: false, error: "Rate limited", retry_after: e.retry_after }
    rescue ServiceError => e
      log_error("Service error", e)
      { success: false, error: e.message }
    end

    # Check if a specific TLD is supported by CleanDNS
    def tld_supported?(tld_name)
      tld = Phish::Tld.find_by(name: tld_name.to_s.downcase)
      tld&.cleandns_supported? || false
    end

    private

    def fetch_abuse_clients
      conn = connection(
        base_url: BASE_URL,
        headers: auth_headers
      )

      get(conn, "/v2/abuse/clients")
    end

    def auth_headers
      api_key = Rails.application.credentials.dig(:cleandns, :api_key)

      headers = {}
      headers["Authorization"] = "Bearer #{api_key}" if api_key.present?
      headers
    end

    def process_response(response)
      unless response.is_a?(Array)
        return { success: false, error: "Invalid response format" }
      end

      # Collect all supported TLDs with their registrars/resellers
      tld_data = {}

      response.each do |group|
        tlds = group["tlds"] || []
        registrars = group["registrars"] || []
        resellers = group["resellers"] || []

        tlds.each do |tld_name|
          normalized = tld_name.to_s.strip.downcase
          next if normalized.blank?

          tld_data[normalized] ||= { registrars: Set.new, resellers: Set.new }
          tld_data[normalized][:registrars].merge(registrars)
          tld_data[normalized][:resellers].merge(resellers)
        end
      end

      # Update database
      stats = update_tld_records(tld_data)

      log_info(
        "CleanDNS TLD sync complete: " \
        "#{stats[:created]} created, #{stats[:updated]} updated, " \
        "#{stats[:supported_tlds]} supported"
      )

      { success: true }.merge(stats)
    end

    def update_tld_records(tld_data)
      created = 0
      updated = 0
      supported_tlds = tld_data.keys

      # Mark all existing TLDs as not supported (will re-enable supported ones)
      Phish::Tld.where(cleandns_supported: true).update_all(cleandns_supported: false)

      tld_data.each do |tld_name, data|
        tld = Phish::Tld.find_by(name: tld_name)

        if tld
          tld.update_from_cleandns!(
            registrars_list: data[:registrars].to_a,
            resellers_list: data[:resellers].to_a,
            supported: true
          )
          updated += 1
        else
          Phish::Tld.create!(
            name: tld_name,
            cleandns_supported: true,
            registrars: data[:registrars].to_a,
            resellers: data[:resellers].to_a,
            cleandns_synced_at: Time.current
          )
          created += 1
        end
      end

      { created: created, updated: updated, supported_tlds: supported_tlds.length }
    end
  end
end
