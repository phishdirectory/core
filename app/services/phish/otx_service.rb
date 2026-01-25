# frozen_string_literal: true

module Phish
  # Service for interacting with AlienVault OTX (Open Threat Exchange)
  # Used to add phishing indicators to our OTX pulse
  #
  # API Documentation: https://otx.alienvault.com/api
  class OtxService < BaseService
    OTX_BASE_URL = "https://otx.alienvault.com"

    # OTX indicator roles
    # See: https://otx.alienvault.com/api
    ROLES = {
      "phishing" => "phishing",
      "suspicious" => "phishing",
      "malware" => "malware",
      "c2" => "c2",
      "spam" => "spam"
    }.freeze

    DEFAULT_ROLE = "phishing"

    # Add a domain indicator to the configured OTX pulse
    def add_domain(domain, role: DEFAULT_ROLE)
      add_indicator(domain, type: "domain", role: role)
    end

    # Add a URL indicator to the configured OTX pulse
    def add_url(url, role: DEFAULT_ROLE)
      add_indicator(url, type: "URL", role: role)
    end

    # Add multiple domain indicators in a single request
    def add_domains(domains, role: DEFAULT_ROLE)
      add_indicators(domains.map { |d| { indicator: d, type: "domain", role: role } })
    end

    # Add multiple URL indicators in a single request
    def add_urls(urls, role: DEFAULT_ROLE)
      add_indicators(urls.map { |u| { indicator: u, type: "URL", role: role } })
    end

    # Map verdict classification to OTX role
    def self.role_for_classification(classification)
      ROLES[classification] || DEFAULT_ROLE
    end

    # Check if the service is configured
    def configured?
      api_key.present? && pulse_id.present?
    end

    # Not a checking service - these return nil
    def check_domain(_domain)
      nil
    end

    def check_url(_url)
      nil
    end

    private

    def add_indicator(indicator, type:, role: "phishing")
      return { success: false, error: "OTX not configured" } unless configured?

      with_error_handling do
        response = otx_connection.patch("/api/v1/pulses/#{pulse_id}") do |req|
          req.body = {
            indicators: {
              add: [
                { indicator: indicator, type: type, role: role }
              ]
            }
          }
        end

        log_info("Added #{type} indicator: #{indicator}")
        { success: true, response: response.body }
      end
    rescue ServiceError => e
      log_error("Failed to add indicator", e)
      { success: false, error: e.message }
    end

    def add_indicators(indicators)
      return { success: false, error: "OTX not configured" } unless configured?
      return { success: true, added: 0 } if indicators.empty?

      with_error_handling do
        response = otx_connection.patch("/api/v1/pulses/#{pulse_id}") do |req|
          req.body = {
            indicators: {
              add: indicators
            }
          }
        end

        log_info("Added #{indicators.size} indicators to OTX pulse")
        { success: true, added: indicators.size, response: response.body }
      end
    rescue ServiceError => e
      log_error("Failed to add indicators", e)
      { success: false, error: e.message }
    end

    def otx_connection
      @otx_connection ||= connection(
        base_url: OTX_BASE_URL,
        headers: {
          "X-OTX-API-KEY" => api_key,
          "Content-Type" => "application/json"
        }
      )
    end

    def api_key
      @api_key ||= Rails.application.credentials.dig(:otx, :api_key)
    end

    def pulse_id
      @pulse_id ||= Rails.application.credentials.dig(:otx, :pulse_id)
    end
  end
end
