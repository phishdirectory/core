# frozen_string_literal: true

module Api
  module V1
    module Auth
      class AuthController < ActionController::API
        # No authentication required for these endpoints - they provide authentication

        # POST /api/v1/auth/authenticate
        # Service-to-service authentication using service API key
        def authenticate
          api_key = extract_api_key
          service_key = Service::Key.authenticate(api_key)

          if service_key
            render json: {
              authenticated: true,
              service: {
                id: service_key.service.id,
                name: service_key.service.name
              },
              key_id: service_key.id
            }
          else
            render json: { error: "Invalid API key" }, status: :unauthorized
          end
        end

        # POST /api/v1/auth/token
        # Exchange credentials for an access token (Doorkeeper OAuth flow)
        def token
          # For now, this is a pass-through to Doorkeeper's token endpoint
          # In a full implementation, this would handle custom token issuance
          render json: {
            error: "Use /oauth/token for OAuth 2.0 token exchange"
          }, status: :not_implemented
        end

        # POST /api/v1/auth/refresh
        # Refresh an expired access token
        def refresh
          # For now, this is a pass-through to Doorkeeper's token endpoint
          # In a full implementation, this would handle token refresh
          render json: {
            error: "Use /oauth/token with grant_type=refresh_token for token refresh"
          }, status: :not_implemented
        end

        private

        def extract_api_key
          # Check Authorization header (Bearer token)
          auth_header = request.headers["Authorization"]
          if auth_header&.start_with?("Bearer ")
            return auth_header.delete_prefix("Bearer ")
          end

          # Check X-API-Key header
          request.headers["X-API-Key"].presence ||
            request.headers["X-Api-Key"].presence ||
            params[:api_key].presence
        end
      end
    end
  end
end
