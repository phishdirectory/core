# frozen_string_literal: true

module API
  module V1
    class Health < Grape::API
      resource :health do
        desc 'Health check endpoint',
          success: { code: 200, message: 'System is healthy' },
          failure: { code: 503, message: 'System is unhealthy' },
          tags: ['System'],
          notes: 'Check the health status of the API and its dependencies'

        get do
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

          status_code = health_status[:checks].values.all? { |check| check[:status] == "healthy" } ? 200 : 503
          
          status status_code
          success_response(health_status)
        end
      end

      helpers do
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
end