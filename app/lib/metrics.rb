# frozen_string_literal: true

# Metrics: Centralized metrics helper wrapping StatsD
#
# Provides a clean, consistent API for recording application metrics.
# All metrics are prefixed and tagged for easy filtering in your metrics backend.
#
# Usage:
#   Metrics.increment("user.signup")
#   Metrics.gauge("queue.size", queue.length)
#   Metrics.measure("api.request") { expensive_operation }
#   Metrics.histogram("response.size", response.body.size)
#   Metrics.time("service.call") { external_api.call }
#
# Tags:
#   Metrics.increment("api.request", tags: { endpoint: "check", version: "v1" })

module Metrics
  class << self
    # Count occurrences of an event
    # @param name [String] Metric name
    # @param value [Integer] Amount to increment (default: 1)
    # @param tags [Hash, Array] Dimensional tags
    def increment(name, value = 1, tags: {})
      StatsD.increment(name, value, tags: normalize_tags(tags))
    rescue => e
      Rails.logger.warn("[Metrics] Failed to record increment: #{e.message}")
    end

    # Decrement a counter
    # @param name [String] Metric name
    # @param value [Integer] Amount to decrement (default: 1)
    # @param tags [Hash, Array] Dimensional tags
    def decrement(name, value = 1, tags: {})
      StatsD.increment(name, -value, tags: normalize_tags(tags))
    rescue => e
      Rails.logger.warn("[Metrics] Failed to record decrement: #{e.message}")
    end

    # Track current value of something (point-in-time)
    # @param name [String] Metric name
    # @param value [Numeric] Current value
    # @param tags [Hash, Array] Dimensional tags
    def gauge(name, value, tags: {})
      StatsD.gauge(name, value, tags: normalize_tags(tags))
    rescue => e
      Rails.logger.warn("[Metrics] Failed to record gauge: #{e.message}")
    end

    # Measure timing of a block (milliseconds)
    # @param name [String] Metric name
    # @param tags [Hash, Array] Dimensional tags
    # @yield Block to measure
    # @return Result of the block
    def measure(name, tags: {}, &block)
      StatsD.measure(name, tags: normalize_tags(tags), &block)
    rescue => e
      Rails.logger.warn("[Metrics] Failed to record measure: #{e.message}")
      yield # Still execute the block
    end

    # Track distribution of values (for percentiles, etc.)
    # @param name [String] Metric name
    # @param value [Numeric] Value to record
    # @param tags [Hash, Array] Dimensional tags
    def histogram(name, value, tags: {})
      StatsD.histogram(name, value, tags: normalize_tags(tags))
    rescue => e
      Rails.logger.warn("[Metrics] Failed to record histogram: #{e.message}")
    end

    # Track unique values (cardinality)
    # @param name [String] Metric name
    # @param value [String] Unique value to track
    # @param tags [Hash, Array] Dimensional tags
    def set(name, value, tags: {})
      StatsD.set(name, value, tags: normalize_tags(tags))
    rescue => e
      Rails.logger.warn("[Metrics] Failed to record set: #{e.message}")
    end

    # Time a block and record duration
    # Uses Process.clock_gettime for precision
    # @param name [String] Metric name
    # @param tags [Hash, Array] Dimensional tags
    # @yield Block to time
    # @return Result of the block
    def time(name, tags: {})
      start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = yield
      duration_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000).round(2)
      histogram("#{name}.duration_ms", duration_ms, tags: tags)
      result
    rescue => e
      Rails.logger.warn("[Metrics] Failed to record time: #{e.message}")
      yield
    end

    # Record an event (combines increment with contextual data)
    # @param name [String] Event name
    # @param tags [Hash] Event tags
    def event(name, tags: {})
      increment("events.#{name}", tags: tags)
    end

    # Record API metrics (common pattern)
    # @param endpoint [String] API endpoint name
    # @param status [Integer] HTTP status code
    # @param duration_ms [Numeric] Request duration in milliseconds
    def api_request(endpoint:, status:, duration_ms:, method: "GET")
      tags = {
        endpoint: endpoint,
        status: status,
        status_class: "#{status / 100}xx",
        method: method.upcase
      }
      increment("api.requests", tags: tags)
      histogram("api.duration_ms", duration_ms, tags: tags)
    end

    # Record a phishing check
    # @param source [String] Check source (walshy, virustotal, etc.)
    # @param result [Symbol] Check result (:phishing, :safe, :unknown)
    # @param duration_ms [Numeric] Check duration
    def phish_check(source:, result:, duration_ms:)
      tags = { source: source, result: result.to_s }
      increment("phish.checks", tags: tags)
      histogram("phish.check_duration_ms", duration_ms, tags: tags)
    end

    private

    # Normalize tags to array format expected by StatsD
    def normalize_tags(tags)
      case tags
      when Hash
        tags.map { |k, v| "#{k}:#{v}" }
      when Array
        tags
      else
        []
      end
    end
  end
end
