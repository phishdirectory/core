# frozen_string_literal: true

module Api
  module V1
    class BaseController < Api::BaseController
      # Authentication for API endpoints
      before_action :authenticate_api_request!

      private

      def authenticate_api_request!
        # Skip authentication for health check and auth endpoints
        return if skip_authentication?
        
        # Check for API key in headers or params
        api_key = request.headers['X-API-Key'] || params[:api_key]
        
        if api_key.blank?
          render_error("API key required", :unauthorized)
          return
        end

        # Find the user API key
        user_api_key = UserApiKey.includes(:user).find_by_key(api_key)
        
        unless user_api_key&.valid?
          render_error("Invalid, expired, or inactive API key", :unauthorized)
          return
        end

        # Update last used timestamp
        user_api_key.touch_last_used!
        
        # Set current user and API key for use in controllers
        @current_user = user_api_key.user
        @current_user_api_key = user_api_key
      end

      def skip_authentication?
        (controller_name == 'health' && action_name == 'index') ||
        (controller_name == 'auth' && action_name == 'authenticate') ||
        (controller_name == 'docs')
      end

      def current_user
        @current_user
      end

      def current_user_api_key
        @current_user_api_key
      end

      def require_admin!
        unless current_user&.admin?
          render_error("Admin access required", :forbidden)
        end
      end

      def require_staff!
        unless current_user&.staff?
          render_error("Staff access required", :forbidden)
        end
      end

      def filtered_headers
        request.headers.to_h.except(
          'HTTP_AUTHORIZATION',
          'HTTP_X_API_KEY',
          'HTTP_COOKIE'
        )
      end
    end
  end
end