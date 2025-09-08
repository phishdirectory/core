# frozen_string_literal: true

module ApiRateLimiting
  extend ActiveSupport::Concern

  included do
    before_action :check_rate_limit
  end

  private

  def check_rate_limit
    return unless should_rate_limit?

    rate_limit_key = "api_rate_limit:#{rate_limit_identifier}"
    current_requests = Rails.cache.read(rate_limit_key) || 0

    if current_requests >= rate_limit_threshold
      render json: {
        success: false,
        error: {
          message: "Rate limit exceeded",
          details: ["Too many requests. Please try again later."]
        }
      }, status: :too_many_requests
      return
    end

    # Increment counter
    Rails.cache.write(
      rate_limit_key,
      current_requests + 1,
      expires_in: rate_limit_window
    )
  end

  def should_rate_limit?
    # Skip rate limiting for health checks
    !(controller_name == "health" && action_name == "index")
  end

  def rate_limit_identifier
    @current_service_key&.id || request.remote_ip
  end

  def rate_limit_threshold
    # Different limits based on authentication
    if @current_service_key
      1000 # Higher limit for authenticated API keys
    else
      100  # Lower limit for unauthenticated requests
    end
  end

  def rate_limit_window
    1.hour
  end
end
