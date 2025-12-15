# frozen_string_literal: true

Sentry.init do |config|
  config.dsn = Rails.application.credentials.dig(:sentry, :dsn) || ENV["SENTRY_DSN"]

  # Skip initialization if no DSN configured
  return unless config.dsn

  config.breadcrumbs_logger = [:active_support_logger, :http_logger]

  # Set traces_sample_rate for performance monitoring
  # Adjust this value in production
  config.traces_sample_rate = Rails.env.production? ? 0.1 : 1.0

  # Set profiles_sample_rate for profiling
  config.profiles_sample_rate = Rails.env.production? ? 0.1 : 1.0

  # Environment
  config.environment = Rails.env

  # Release version (set via environment or git)
  config.release = ENV.fetch("RELEASE_VERSION") { `git rev-parse --short HEAD`.strip rescue nil }

  # Filter sensitive parameters
  config.send_default_pii = false

  # Exclude common bot/scanner errors
  config.excluded_exceptions += [
    "ActionController::RoutingError",
    "ActionController::InvalidAuthenticityToken",
    "ActionController::BadRequest",
    "ActiveRecord::RecordNotFound"
  ]

  # Set user context
  config.before_send = lambda do |event, hint|
    # Add user context if available
    if (user = hint[:rack_env]["warden"]&.user rescue nil)
      event.user = {
        id: user.pd_id,
        email: user.email,
        username: user.username
      }
    end

    event
  end
end
