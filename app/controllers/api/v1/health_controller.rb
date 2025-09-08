# frozen_string_literal: true

module Api
  module V1
    class HealthController < BaseController
      skip_before_action :authenticate_api_key

      def index
        health_status = {
          status: "healthy",
          timestamp: Time.current.iso8601,
          version: "1.0.0",
          environment: Rails.env,
          checks: {
            database: database_check,
            redis: redis_check
          }
        }

        status_code = health_status[:checks].values.all? { |check| check[:status] == "healthy" } ? :ok : :service_unavailable
        
        render_success(health_status, status_code)
      end

      private

      def database_check
        start_time = Time.current
        ActiveRecord::Base.connection.execute("SELECT 1")
        {
          status: "healthy",
          response_time_ms: ((Time.current - start_time) * 1000).round(2)
        }
      rescue => e
        {
          status: "unhealthy",
          error: e.message
        }
      end

      def redis_check
        if defined?(Redis)
          start_time = Time.current
          Redis.current.ping
          {
            status: "healthy",
            response_time_ms: ((Time.current - start_time) * 1000).round(2)
          }
        else
          {
            status: "not_configured"
          }
        end
      rescue => e
        {
          status: "unhealthy",
          error: e.message
        }
      end
    end
  end
end