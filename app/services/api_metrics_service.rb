# frozen_string_literal: true

# Service for collecting and reporting API metrics
# Integrates with StatsD for metrics collection
class ApiMetricsService
  class << self
    # Record an API request
    def record_request(endpoint:, method:, status:, duration_ms:, authenticated: false, service: nil)
      tags = build_tags(endpoint: endpoint, method: method, status: status, authenticated: authenticated, service: service)

      # Increment request counter
      increment("api.requests", tags: tags)

      # Record response time histogram
      histogram("api.request_duration_ms", duration_ms, tags: tags)

      # Record status code counters
      increment("api.status.#{status_category(status)}", tags: tags)
    end

    # Record API authentication event
    def record_auth(type:, success:, service: nil)
      tags = { auth_type: type, success: success }
      tags[:service] = service if service

      increment("api.auth", tags: tags)
    end

    # Record rate limit hit
    def record_rate_limit(endpoint:, ip: nil, api_key_id: nil)
      tags = { endpoint: endpoint }
      tags[:ip_hash] = Digest::SHA256.hexdigest(ip)[0..7] if ip
      tags[:key_id] = api_key_id if api_key_id

      increment("api.rate_limited", tags: tags)
    end

    # Record webhook delivery
    def record_webhook(event:, success:, duration_ms: nil, service_id: nil)
      tags = { event: event, success: success }
      tags[:service_id] = service_id if service_id

      increment("webhooks.delivered", tags: tags)
      histogram("webhooks.duration_ms", duration_ms, tags: tags) if duration_ms
    end

    # Record phish check
    def record_phish_check(type:, verdict:, service: nil, cached: false)
      tags = { type: type, verdict: verdict, cached: cached }
      tags[:service] = service if service

      increment("phish.checks", tags: tags)
    end

    # Record error
    def record_error(type:, message: nil, context: {})
      tags = { error_type: type }.merge(context.slice(:endpoint, :service, :method))

      increment("api.errors", tags: tags)

      Rails.logger.error("[ApiMetrics] Error recorded: #{type} - #{message}")
    end

    # Flush any batched metrics (called periodically)
    def flush
      # StatsD typically auto-flushes, but this hook is available
      # for custom batching implementations
    end

    private

    def increment(metric, tags: {})
      if defined?(StatsD) && StatsD.respond_to?(:increment)
        StatsD.increment(metric, tags: format_tags(tags))
      else
        Rails.logger.debug("[Metrics] #{metric} +1 #{tags}")
      end
    rescue StandardError => e
      Rails.logger.warn("[ApiMetrics] Failed to increment metric: #{e.message}")
    end

    def histogram(metric, value, tags: {})
      if defined?(StatsD) && StatsD.respond_to?(:histogram)
        StatsD.histogram(metric, value, tags: format_tags(tags))
      elsif defined?(StatsD) && StatsD.respond_to?(:distribution)
        StatsD.distribution(metric, value, tags: format_tags(tags))
      else
        Rails.logger.debug("[Metrics] #{metric} = #{value} #{tags}")
      end
    rescue StandardError => e
      Rails.logger.warn("[ApiMetrics] Failed to record histogram: #{e.message}")
    end

    def format_tags(tags)
      tags.compact.transform_values(&:to_s)
    end

    def build_tags(endpoint:, method:, status:, authenticated:, service:)
      tags = {
        endpoint: sanitize_endpoint(endpoint),
        method: method.to_s.upcase,
        status: status.to_s,
        authenticated: authenticated.to_s
      }
      tags[:service] = service if service
      tags
    end

    def sanitize_endpoint(endpoint)
      # Remove IDs and sensitive data from endpoints for aggregation
      endpoint
        .gsub(%r{/[0-9a-f-]{36}}, "/:id")  # UUIDs
        .gsub(%r{/\d+}, "/:id")             # Numeric IDs
        .gsub(/\?.*/, "")                   # Query strings
    end

    def status_category(status)
      case status.to_i
      when 200..299 then "2xx"
      when 300..399 then "3xx"
      when 400..499 then "4xx"
      when 500..599 then "5xx"
      else "unknown"
      end
    end
  end
end
