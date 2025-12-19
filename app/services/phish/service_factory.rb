# frozen_string_literal: true

module Phish
  # Factory for instantiating phishing detection services.
  # Centralizes service registration and instantiation to avoid duplication
  # across AggregatorService and job classes.
  class ServiceFactory
    # Registry of available services and their classes
    SERVICE_REGISTRY = {
      walshy: "Phish::WalshyService",
      google_safe_browsing: "Phish::GoogleSafeBrowsingService",
      virustotal: "Phish::VirustotalService",
      urlscan: "Phish::UrlscanService",
      fish_fish: "Phish::FishFishService",
      sinking_yachts: "Phish::SinkingYachtsService",
      openphish: "Phish::OpenphishService"
    }.freeze

    class << self
      # Instantiate a service by name
      # @param name [Symbol, String] The service name
      # @param logger [Logger] Optional logger instance
      # @return [Phish::BaseService, nil] The service instance or nil if unknown
      def build(name, logger: Rails.logger)
        class_name = SERVICE_REGISTRY[name.to_sym]
        return nil unless class_name

        class_name.constantize.new(logger: logger)
      rescue NameError => e
        Rails.logger.error("[ServiceFactory] Failed to instantiate #{name}: #{e.message}")
        nil
      end

      # List all registered service names
      # @return [Array<Symbol>] List of service names
      def registered_services
        SERVICE_REGISTRY.keys
      end

      # Check if a service is registered
      # @param name [Symbol, String] The service name
      # @return [Boolean]
      def registered?(name)
        SERVICE_REGISTRY.key?(name.to_sym)
      end
    end
  end
end
