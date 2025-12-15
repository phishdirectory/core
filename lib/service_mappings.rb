# frozen_string_literal: true

# Service ID to name mappings for service-to-service authentication
# This provides a registry of known services for validation and logging

module ServiceMappings
  SERVICES = {
    # Core phish.directory services
    "phishdirectory-api" => {
      name: "phish.directory API",
      description: "Main phishing detection API"
    },
    "phishdirectory-web" => {
      name: "phish.directory Web",
      description: "Web frontend application"
    },
    "phishdirectory-admin" => {
      name: "phish.directory Admin",
      description: "Admin dashboard"
    },

    # Internal services
    "webhook-processor" => {
      name: "Webhook Processor",
      description: "Processes incoming webhooks"
    },
    "metrics-collector" => {
      name: "Metrics Collector",
      description: "Collects and aggregates metrics"
    },

    # External integrations
    "slack-bot" => {
      name: "Slack Bot",
      description: "Slack integration bot"
    },
    "discord-bot" => {
      name: "Discord Bot",
      description: "Discord integration bot"
    }
  }.freeze

  class << self
    def known_service?(service_name)
      SERVICES.key?(service_name)
    end

    def service_info(service_name)
      SERVICES[service_name]
    end

    def service_display_name(service_name)
      SERVICES.dig(service_name, :name) || service_name.titleize
    end

    def all_services
      SERVICES.keys
    end

    def register_service(id, name:, description: nil)
      SERVICES[id] = { name: name, description: description }
    end
  end
end
