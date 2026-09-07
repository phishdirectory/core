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
  # Claims quota before making the call, not after it.
  #
  # This used to read every counter, make the request, then increment. Two
  # workers could both read a value below the limit, both call the vendor, and
  # both then increment, so the real rate exceeded the configured one whenever
  # more than one worker was checking at once. Against VirusTotal's four
  # requests a minute that is easy to hit.
  #
  # Reserving first means a request that is then abandoned still costs quota,
  # which is the safe direction to be wrong in: we would rather under-use an
  # allowance than get the key banned.
  def with_rate_limit(action: :default)
    reserve_rate_limit!(action: action)
    yield
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
    [ config[:requests] - current, 0 ].max
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
      remaining = [ config[:requests] - current, 0 ].max
      # Estimate reset time based on period since cache TTL APIs are internal
      reset_at = Time.current + config[:period]

      {
        limit: config[:requests],
        remaining: remaining,
        reset_at: reset_at,
        period: config[:period]
      }
    end
  end

  private

  # Takes one slot from every configured window, atomically, and hands back
  # anything it already took if a later window turns out to be exhausted.
  def reserve_rate_limit!(action: :default)
    claimed = []

    _rate_limits.each do |name, config|
      count = claim_slot(cache_key(name, action), config[:period])

      if count > config[:requests]
        release(claimed)
        raise RateLimitExceeded.new(
          limit_name: name,
          retry_after: config[:period],
          limit: config[:requests],
          remaining: 0
        )
      end

      claimed << cache_key(name, action)
    end
  end

  # A single atomic increment. The previous read-then-write left a window in
  # which two callers both saw zero and both wrote 1, and re-created an expired
  # key through `increment` without a TTL, which could pin a service as rate
  # limited indefinitely.
  def claim_slot(key, period)
    Rails.cache.increment(key, 1, expires_in: period) || begin
      # Some stores return nil when the key is absent rather than creating it.
      Rails.cache.write(key, 1, expires_in: period, unless_exist: true)
      Rails.cache.increment(key, 0, expires_in: period).to_i.nonzero? || 1
    end
  end

  def release(keys)
    keys.each { |key| Rails.cache.decrement(key, 1) }
  end

  def cache_key(limit_name, action)
    "rate_limit:#{service_name}:#{action}:#{limit_name}"
  end
end
