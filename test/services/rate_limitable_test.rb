# frozen_string_literal: true

require "test_helper"

# Quota used to be checked, then the call made, then the counter incremented.
# Two workers could both read a value below the limit, both call the vendor,
# and both then increment.
class RateLimitableTest < ActiveSupport::TestCase
  class Limited
    include RateLimitable

    rate_limit :per_minute, requests: 3, period: 60

    def initialize(name)
      @name = name
    end

    def service_name = @name

    def call
      with_rate_limit { :called }
    end
  end

  setup do
    @original_cache = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new
    @service = Limited.new("limited-#{SecureRandom.hex(4)}")
  end

  teardown do
    Rails.cache = @original_cache
  end

  test "calls within the limit are allowed" do
    3.times { assert_equal :called, @service.call }
  end

  test "the call past the limit is refused" do
    3.times { @service.call }

    assert_raises(RateLimitable::RateLimitExceeded) { @service.call }
  end

  test "quota is consumed before the call, not after" do
    # If quota were only consumed on success, a raising call would be free and
    # a failing upstream could be hammered without limit.
    3.times do
      @service.with_rate_limit { raise "upstream boom" }
    rescue RuntimeError
      nil
    end

    assert_raises(RateLimitable::RateLimitExceeded) { @service.call }
  end

  test "concurrent callers cannot both claim the last slot" do
    mutex = Mutex.new
    granted = 0

    threads = 10.times.map do
      Thread.new do
        @service.call
        mutex.synchronize { granted += 1 }
      rescue RateLimitable::RateLimitExceeded
        nil
      end
    end
    threads.each(&:join)

    assert_equal 3, granted,
                 "exactly the configured number of callers should get through"
  end

  test "remaining requests reflects what has been claimed" do
    assert_equal 3, @service.remaining_requests(:per_minute)

    @service.call

    assert_equal 2, @service.remaining_requests(:per_minute)
  end

  test "availability flips once the limit is reached" do
    assert @service.rate_limit_available?

    3.times { @service.call }

    assert_not @service.rate_limit_available?
  end

  test "a separate service has its own budget" do
    other = Limited.new("other-#{SecureRandom.hex(4)}")
    3.times { @service.call }

    assert_equal :called, other.call
  end
end
