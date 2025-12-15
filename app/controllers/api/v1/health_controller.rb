# frozen_string_literal: true

module Api
  module V1
    class HealthController < ActionController::API
      # No authentication required for health checks

      def show
        render json: {
          status: "ok",
          timestamp: Time.current.iso8601,
          version: ENV.fetch("RELEASE_VERSION") { "development" }
        }
      end
    end
  end
end
