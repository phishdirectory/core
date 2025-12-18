# frozen_string_literal: true

module Report
  # Base service for all report-related services
  # Provides common HTTP client functionality using Faraday
  class BaseService
    class ServiceError < StandardError; end
    class TimeoutError < ServiceError; end
    class RateLimitError < ServiceError
      attr_reader :retry_after

      def initialize(message, retry_after: nil)
        @retry_after = retry_after
        super(message)
      end
    end

    DEFAULT_TIMEOUT = 30
    DEFAULT_OPEN_TIMEOUT = 10

    attr_reader :logger

    def initialize(logger: Rails.logger)
      @logger = logger
    end

    def service_name
      self.class.name.demodulize.underscore.sub("_service", "")
    end

    protected

    # Create a Faraday connection with standard configuration
    def connection(base_url:, timeout: DEFAULT_TIMEOUT, headers: {})
      Faraday.new(url: base_url) do |conn|
        conn.options.timeout = timeout
        conn.options.open_timeout = DEFAULT_OPEN_TIMEOUT

        conn.headers["User-Agent"] = user_agent
        conn.headers["Accept"] = "application/json"
        headers.each { |key, value| conn.headers[key] = value }

        conn.request :json
        conn.response :json, content_type: /\bjson$/
        conn.adapter Faraday.default_adapter
      end
    end

    def get(conn, path, params = {})
      with_error_handling do
        response = conn.get(path, params)
        response.body
      end
    end

    def post(conn, path, body = {})
      with_error_handling do
        response = conn.post(path, body)
        response.body
      end
    end

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

    def handle_client_error(error)
      status = error.response[:status]

      case status
      when 429
        retry_after = extract_retry_after(error.response)
        log_error("Rate limited (retry after #{retry_after}s)", error)
        raise RateLimitError.new("#{service_name} rate limit exceeded", retry_after: retry_after)
      else
        log_error("Client error", error)
        raise ServiceError, "#{service_name} client error: #{status}"
      end
    end

    def extract_retry_after(response)
      headers = response[:headers] || {}
      retry_after = headers["retry-after"] || headers["Retry-After"]

      return 60 unless retry_after

      if retry_after.match?(/^\d+$/)
        retry_after.to_i
      else
        begin
          (Time.parse(retry_after) - Time.current).to_i.clamp(1, 3600)
        rescue ArgumentError
          60
        end
      end
    end

    private

    def user_agent
      "@phishdirectory/core/#{ENV.fetch('RELEASE_VERSION', '1.0.0')} (https://phish.directory)"
    end

    def log_error(message, error)
      logger.error("[#{service_name}] #{message}: #{error.message}")
    end

    def log_info(message)
      logger.info("[#{service_name}] #{message}")
    end

    def log_debug(message)
      logger.debug("[#{service_name}] #{message}")
    end
  end
end
