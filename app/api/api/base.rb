# frozen_string_literal: true

module API
  class Base < Grape::API
    format :json
    prefix :api

    # Global rescue handlers
    rescue_from ActiveRecord::RecordNotFound do |e|
      error_response("Resource not found", 404, [e.message])
    end

    rescue_from ActiveRecord::RecordInvalid do |e|
      error_response("Validation failed", 422, e.record.errors.full_messages)
    end

    rescue_from Grape::Exceptions::ValidationErrors do |e|
      error_response("Validation failed", 400, e.full_messages)
    end

    rescue_from :all do |e|
      Rails.logger.error "API Error: #{e.class} - #{e.message}"
      Rails.logger.error e.backtrace.join("\n")
      error_response("Internal server error", 500, ["An unexpected error occurred"])
    end

    # Add API versioning
    mount API::V1::Base

    add_swagger_documentation(
      api_version: "v1",
      hide_documentation_path: true,
      mount_path: "/swagger_doc",
      hide_format: true,
      info: {
        title: "Phish Directory Core API",
        description: "API for Phish Directory authentication and user management",
        contact: {
          name: "API Support",
          email: "support@phish.directory"
        }
      },
      security_definitions: {
        api_key: {
          type: "apiKey",
          name: "X-API-Key",
          in: "header",
          description: "API key for authentication"
        }
      },
      security: [
        {
          api_key: []
        }
      ]
    )

    helpers do
      def error_response(message, status, details = [])
        {
          success: false,
          error: {
            message: message,
            details: details
          }
        }
      end

      def success_response(data = {})
        {
          success: true,
          data: data
        }
      end

      def authenticate!
        api_key = headers["X-Api-Key"] || params[:api_key]
        
        error!("API key required", 401) if api_key.blank?
        
        @current_user_api_key = UserApiKey.includes(:user).find_by_key(api_key)
        
        unless @current_user_api_key&.valid?
          error!("Invalid, expired, or inactive API key", 401)
        end

        @current_user_api_key.touch_last_used!
        @current_user = @current_user_api_key.user
      end

      def current_user
        @current_user
      end

      def current_user_api_key
        @current_user_api_key
      end

      def require_admin!
        error!("Admin access required", 403) unless current_user&.admin?
      end

      def require_staff!
        error!("Staff access required", 403) unless current_user&.staff?
      end
    end
  end
end