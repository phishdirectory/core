# frozen_string_literal: true

module Api
  module V1
    class BaseController < ActionController::API
      include ActionController::HttpAuthentication::Token::ControllerMethods

      before_action :authenticate_request!

      # Error handling
      rescue_from ActiveRecord::RecordNotFound, with: :not_found
      rescue_from ActiveRecord::RecordInvalid, with: :unprocessable_entity
      rescue_from ActionController::ParameterMissing, with: :bad_request

      protected

      attr_reader :current_user, :current_api_key, :current_service, :current_service_key

      def authenticate_request!
        # Try user API key first, then service key
        authenticate_user_api_key || authenticate_service_key || unauthorized!
      end

      def authenticate_user_api_key
        api_key = extract_api_key
        return false unless api_key&.start_with?("pdat_")

        @current_api_key = UserApiKey.authenticate(api_key)
        return false unless @current_api_key

        @current_user = @current_api_key.user
        true
      end

      def authenticate_service_key
        api_key = extract_api_key
        return false if api_key.blank? || api_key.start_with?("pdat_")

        @current_service_key = Service::Key.authenticate(api_key)
        return false unless @current_service_key

        @current_service = @current_service_key.service
        true
      end

      def extract_api_key
        # Check Authorization header (Bearer token)
        authenticate_with_http_token { |token, _options| return token }

        # Check X-API-Key header
        request.headers["X-API-Key"].presence ||
          request.headers["X-Api-Key"].presence ||
          # Check query param (least preferred)
          params[:api_key].presence
      end

      def user_authenticated?
        @current_user.present?
      end

      def service_authenticated?
        @current_service.present?
      end

      def require_user!
        unauthorized!("User authentication required") unless user_authenticated?
      end

      def require_service!
        unauthorized!("Service authentication required") unless service_authenticated?
      end

      # Response helpers
      def unauthorized!(message = "Invalid or missing API key")
        render json: { error: message }, status: :unauthorized
      end

      def not_found
        render json: { error: "Resource not found" }, status: :not_found
      end

      def unprocessable_entity(exception)
        render json: { error: exception.message }, status: :unprocessable_entity
      end

      def bad_request(exception)
        render json: { error: "Missing parameter: #{exception.param}" }, status: :bad_request
      end

      def rate_limited!(retry_after: 60)
        response.headers["Retry-After"] = retry_after.to_s
        render json: { error: "Rate limit exceeded" }, status: :too_many_requests
      end

      # Find a record by public_id or legacy UUID
      # Supports both formats for backwards compatibility
      #
      # @param model_class [Class] The model class to search
      # @param id [String] Either a public_id (e.g., "usr_xxx") or UUID
      # @param prefix [String] Expected prefix for public_id format
      # @return [ActiveRecord::Base] The found record
      # @raise [ActiveRecord::RecordNotFound] If no record found
      def find_by_public_or_uuid!(model_class, id, prefix:)
        if id.to_s.start_with?("#{prefix}_")
          model_class.find_by_public_id!(id)
        else
          model_class.find(id)
        end
      end

      # Log API usage for service keys
      def log_service_usage(response_code:, response_body: nil, duration_ms: nil)
        return unless @current_service_key

        @current_service_key.log_usage(
          user: @current_user,
          request_path: request.path,
          request_method: request.method,
          ip_address: request.remote_ip,
          user_agent: request.user_agent,
          response_code: response_code,
          response_body: response_body&.to_json&.truncate(10_000),
          duration_ms: duration_ms
        )
      end
    end
  end
end
