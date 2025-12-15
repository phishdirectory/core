# frozen_string_literal: true

require "faraday"

module Phish
  # Base service for all phishing detection services
  # Provides common HTTP client functionality using Faraday
  class BaseService
    class ServiceError < StandardError; end
    class TimeoutError < ServiceError; end
    class RateLimitError < ServiceError; end
    class AuthenticationError < ServiceError; end

    DEFAULT_TIMEOUT = 30
    DEFAULT_OPEN_TIMEOUT = 10

    attr_reader :logger

    def initialize(logger: Rails.logger)
      @logger = logger
    end

    # Subclasses must implement this method
    def check_domain(_domain)
      raise NotImplementedError, "Subclasses must implement #check_domain"
    end

    # Subclasses must implement this method
    def check_url(_url)
      raise NotImplementedError, "Subclasses must implement #check_url"
    end

    # Service name for logging and metrics
    def service_name
      self.class.name.demodulize.underscore.sub("_service", "")
    end

    protected

    # Create a Faraday connection with standard configuration
    def connection(base_url:, timeout: DEFAULT_TIMEOUT, headers: {})
      Faraday.new(url: base_url) do |conn|
        conn.options.timeout = timeout
        conn.options.open_timeout = DEFAULT_OPEN_TIMEOUT

        # Set standard headers
        conn.headers["User-Agent"] = user_agent
        conn.headers["Accept"] = "application/json"
        headers.each { |key, value| conn.headers[key] = value }

        # Request middleware
        conn.request :json

        # Response middleware
        conn.response :json, content_type: /\bjson$/
        conn.response :raise_error

        # Adapter (must be last)
        conn.adapter Faraday.default_adapter
      end
    end

    # Make a GET request with error handling
    def get(conn, path, params = {})
      with_error_handling do
        response = conn.get(path, params)
        response.body
      end
    end

    # Make a POST request with error handling
    def post(conn, path, body = {})
      with_error_handling do
        response = conn.post(path, body)
        response.body
      end
    end

    # Standard error handling wrapper
    def with_error_handling
      yield
    rescue Faraday::TimeoutError => e
      log_error("Request timed out", e)
      raise TimeoutError, "Request to #{service_name} timed out"
    rescue Faraday::ClientError => e
      handle_client_error(e)
    rescue Faraday::ServerError => e
      log_error("Server error", e)
      raise ServiceError, "#{service_name} server error: #{e.response[:status]}"
    rescue StandardError => e
      log_error("Unexpected error", e)
      raise ServiceError, "#{service_name} error: #{e.message}"
    end

    # Handle client errors (4xx responses)
    def handle_client_error(error)
      status = error.response[:status]

      case status
      when 401, 403
        log_error("Authentication failed", error)
        raise AuthenticationError, "#{service_name} authentication failed"
      when 429
        log_error("Rate limited", error)
        raise RateLimitError, "#{service_name} rate limit exceeded"
      else
        log_error("Client error", error)
        raise ServiceError, "#{service_name} client error: #{status}"
      end
    end

    # Normalize domain (remove protocol, path, etc.)
    def normalize_domain(domain)
      domain = domain.to_s.strip.downcase
      domain = domain.sub(%r{\Ahttps?://}, "")
      domain = domain.split("/").first
      domain = domain.split(":").first
      domain
    end

    # Normalize URL
    def normalize_url(url)
      url = url.to_s.strip
      url = "https://#{url}" unless url.match?(%r{\Ahttps?://})
      uri = URI.parse(url)
      uri.host = uri.host&.downcase
      uri.to_s
    rescue URI::InvalidURIError
      url
    end

    # Create a verdict result hash
    def build_result(verdict:, confidence: nil, details: {})
      {
        service: service_name,
        verdict: verdict,
        confidence: confidence,
        details: details,
        checked_at: Time.current
      }
    end

    private

    def user_agent
      "@phishdirectory/core/#{ENV.fetch('RELEASE_VERSION', '1.0.0')} (https://phish.directory)"
    end

    def log_error(message, error)
      logger.error("[#{service_name}] #{message}: #{error.message}")
      logger.debug(error.backtrace&.first(5)&.join("\n")) if logger.debug?
    end

    def log_info(message)
      logger.info("[#{service_name}] #{message}")
    end
  end
end
