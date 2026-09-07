# frozen_string_literal: true

# Error tracking.
#
# There was none. When a job exhausted its retries, when an API request 500'd,
# when a feed sync quietly returned nothing, the only record was a log line
# nobody was reading. Most of what a recent audit found by reading source would
# have announced itself with this installed.
#
# Configured entirely from credentials or the environment. With no DSN set the
# SDK stays inert, so development and test are unaffected and a missing secret
# cannot break boot.
dsn = Rails.application.credentials.dig(:sentry, :dsn) || ENV["SENTRY_DSN"]

if dsn.present?
  Sentry.init do |config|
    config.dsn = dsn
    config.enabled_environments = %w[production staging]

    config.breadcrumbs_logger = %i[active_support_logger http_logger]

    # Sample rather than send everything; raise if the volume turns out to be
    # manageable and the traces are useful.
    config.traces_sample_rate = (ENV["SENTRY_TRACES_SAMPLE_RATE"] || 0.1).to_f

    config.release = ENV["RELEASE_VERSION"].presence

    # The same list that keeps secrets out of the Rails log and out of
    # api_requests. Error reports are one more place a password could land.
    filter = ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters)
    config.before_send = lambda do |event, _hint|
      event.request&.data = filter.filter(event.request.data) if event.request&.data.is_a?(Hash)
      event
    end

    # Health checks and asset requests are noise.
    config.excluded_exceptions += [
      "ActionController::RoutingError",
      "ActiveRecord::RecordNotFound"
    ]
  end
else
  Rails.logger.info("[Sentry] No DSN configured, error reporting is disabled") if Rails.env.production?
end
