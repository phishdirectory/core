# frozen_string_literal: true

require "resolv"
require "faraday"

module Domain
  # Service to check if a domain is currently available (DNS resolvable and HTTP reachable)
  # Used for tracking domain takedowns and uptime monitoring
  #
  # @example
  #   result = Domain::AvailabilityService.check("example.com")
  #   # => { domain: "example.com", dns: { resolvable: true, ... }, http: { reachable: true, ... }, ... }
  #
  class AvailabilityService
    DEFAULT_DNS_TIMEOUT = 5
    DEFAULT_HTTP_TIMEOUT = 10

    class << self
      def check(domain, dns_timeout: DEFAULT_DNS_TIMEOUT, http_timeout: DEFAULT_HTTP_TIMEOUT)
        new(domain, dns_timeout: dns_timeout, http_timeout: http_timeout).check
      end
    end

    def initialize(domain, dns_timeout: DEFAULT_DNS_TIMEOUT, http_timeout: DEFAULT_HTTP_TIMEOUT)
      @domain = normalize_domain(domain)
      @dns_timeout = dns_timeout
      @http_timeout = http_timeout
    end

    def check
      dns_result = check_dns
      http_result = dns_result[:resolvable] ? check_http : { reachable: false, status: nil, error: "DNS not resolvable" }

      {
        domain: @domain,
        dns: dns_result,
        http: http_result,
        available: dns_result[:resolvable] && http_result[:reachable],
        checked_at: Time.current
      }
    end

    private

    def normalize_domain(domain)
      domain = domain.to_s.strip.downcase
      domain = domain.sub(%r{\Ahttps?://}, "")
      domain = domain.split("/").first
      domain = domain.split(":").first
      domain
    end

    def check_dns
      Timeout.timeout(@dns_timeout) do
        resolver = Resolv::DNS.new
        addresses = resolver.getaddresses(@domain)

        {
          resolvable: addresses.any?,
          addresses: addresses.map(&:to_s),
          error: nil
        }
      end
    rescue Resolv::ResolvError => e
      { resolvable: false, addresses: [], error: e.message }
    rescue Timeout::Error
      { resolvable: false, addresses: [], error: "DNS lookup timed out" }
    rescue StandardError => e
      { resolvable: false, addresses: [], error: e.message }
    end

    def check_http
      conn = Faraday.new do |f|
        f.options.timeout = @http_timeout
        f.options.open_timeout = 5
        f.response :follow_redirects, limit: 3
        f.adapter Faraday.default_adapter
      end

      # Try HTTPS first, fall back to HTTP
      response = begin
        conn.head("https://#{@domain}")
      rescue Faraday::Error
        conn.head("http://#{@domain}")
      end

      {
        reachable: response.status.between?(100, 599),
        status: response.status,
        error: nil
      }
    rescue Faraday::TimeoutError
      { reachable: false, status: nil, error: "HTTP request timed out" }
    rescue Faraday::ConnectionFailed => e
      { reachable: false, status: nil, error: "Connection failed: #{e.message}" }
    rescue StandardError => e
      { reachable: false, status: nil, error: e.message }
    end
  end
end
