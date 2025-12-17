# frozen_string_literal: true

# Shared rate limiting functionality for external API services
# Uses Rails.cache for distributed rate limit tracking
#
# Usage in a service:
#   class MyService < Phish::BaseService
#     include RateLimitable
#
#     rate_limit :default,    requests: 100, period: 1.minute
#     rate_limit :daily,      requests: 1000, period: 1.day
#
#     def call
#       with_rate_limit do
#         # API call here
#       end
#     end
#   end
#
module RateLimitable
  extend ActiveSupport::Concern

  class RateLimitExceeded < StandardError
    attr_reader :limit_name, :retry_after, :limit, :remaining

    def initialize(limit_name:, retry_after:, limit:, remaining: 0)
      @limit_name = limit_name
      @retry_after = retry_after
      @limit = limit
      @remaining = remaining
      super("Rate limit '#{limit_name}' exceeded. Retry after #{retry_after} seconds.")
    end
  end

  included do
    class_attribute :_rate_limits, default: {}
  end

  class_methods do
    # Define a rate limit for this service
    #
    # @param name [Symbol] Unique name for this limit (e.g., :minute, :daily)
    # @param requests [Integer] Maximum requests allowed
    # @param period [ActiveSupport::Duration] Time window
    #
    def rate_limit(name, requests:, period:)
      self._rate_limits = _rate_limits.merge(
        name => { requests: requests, period: period.to_i }
      )
    end
  end

  # Execute block if rate limits allow, otherwise raise RateLimitExceeded
  #
  # @param action [Symbol] Optional action name for more granular limits
  # @yield Block to execute if within rate limits
  # @return [Object] Result of the block
  #
  def with_rate_limit(action: :default)
    check_rate_limits!(action: action)
    result = yield
    increment_counters(action: action)
    result
  end

  # Check if request would be allowed without consuming quota
  #
  # @param action [Symbol] Optional action name
  # @return [Boolean] true if request would be allowed
  #
  def rate_limit_available?(action: :default)
    _rate_limits.all? do |name, config|
      remaining = remaining_requests(name, action: action)
      remaining.nil? || remaining > 0
    end
  end

  # Get remaining requests for a specific limit
  #
  # @param limit_name [Symbol] Name of the limit
  # @param action [Symbol] Optional action name
  # @return [Integer, nil] Remaining requests, or nil if limit not configured
  #
  def remaining_requests(limit_name, action: :default)
    config = _rate_limits[limit_name]
    return nil unless config

    key = cache_key(limit_name, action)
    current = Rails.cache.read(key).to_i
    [config[:requests] - current, 0].max
  end

  # Get rate limit status for all configured limits
  #
  # @param action [Symbol] Optional action name
  # @return [Hash] Status for each limit
  #
  def rate_limit_status(action: :default)
    _rate_limits.transform_values.with_index do |(name, config), _|
      key = cache_key(name, action)
      current = Rails.cache.read(key).to_i
      remaining = [config[:requests] - current, 0].max
      ttl = Rails.cache.send(:read_entry, key, {})&.expires_at
      reset_at = ttl ? Time.at(ttl) : Time.current + config[:period]

      {
        limit: config[:requests],
        remaining: remaining,
        reset_at: reset_at,
        period: config[:period]
      }
    end
  end

  private

  def check_rate_limits!(action: :default)
    _rate_limits.each do |name, config|
      key = cache_key(name, action)
      current = Rails.cache.read(key).to_i

      if current >= config[:requests]
        # Calculate retry_after based on cache TTL
        entry = Rails.cache.send(:read_entry, key, {})
        expires_at = entry&.expires_at || (Time.current.to_i + config[:period])
        retry_after = [(expires_at - Time.current.to_i), 1].max

        raise RateLimitExceeded.new(
          limit_name: name,
          retry_after: retry_after,
          limit: config[:requests],
          remaining: 0
        )
      end
    end
  end

  def increment_counters(action: :default)
    _rate_limits.each do |name, config|
      key = cache_key(name, action)
      current = Rails.cache.read(key).to_i

      if current.zero?
        # First request in window - set with expiration
        Rails.cache.write(key, 1, expires_in: config[:period])
      else
        # Increment existing counter
        Rails.cache.increment(key)
      end
    end
  end

  def cache_key(limit_name, action)
    "rate_limit:#{service_name}:#{action}:#{limit_name}"
  end
end
