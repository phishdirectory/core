# frozen_string_literal: true

# Lograge: Structured logging for Rails
# Transforms verbose Rails logs into structured, parseable format
#
# In production: JSON format for log aggregation (DataDog, Splunk, etc.)
# In development: Key-value format for readability

Rails.application.configure do
  config.lograge.enabled = true

  # Use JSON formatter in production for log aggregation systems
  if Rails.env.production?
    config.lograge.formatter = Lograge::Formatters::Json.new
  end

  # Include additional custom data in every log line
  config.lograge.custom_options = lambda do |event|
    {
      request_id: event.payload[:request_id],
      user_id: event.payload[:user_id],
      service_id: event.payload[:service_id],
      ip: event.payload[:ip],
      host: event.payload[:host],
      user_agent: event.payload[:user_agent]
    }.compact
  end

  # Add custom payload data from controllers
  # Controllers can set these via append_info_to_payload
  config.lograge.custom_payload do |controller|
    {
      request_id: controller.request.request_id,
      user_id: controller.try(:current_user)&.id,
      service_id: controller.try(:current_service)&.id,
      ip: controller.request.remote_ip,
      host: controller.request.host,
      user_agent: controller.request.user_agent
    }
  end

  # Ignore specific paths (health checks, assets)
  config.lograge.ignore_actions = [
    "OkComputer::OkComputerController#index",
    "OkComputer::OkComputerController#show"
  ]
end
