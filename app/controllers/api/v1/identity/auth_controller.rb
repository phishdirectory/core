# frozen_string_literal: true

module Api
  module V1
    module Identity
      class AuthController < BaseController
        before_action :require_service!
        before_action :check_identity_api_enabled!

        # POST /api/v1/identity/authenticate
        # Verify user credentials (email + password)
        def authenticate
          email = params[:email]&.strip&.downcase
          password = params[:password]

          if email.blank? || password.blank?
            render json: { error: "Email and password are required" }, status: :bad_request
            return
          end

          user = User.find_by(email: email)

          if user.nil?
            render json: { authenticated: false }, status: :unauthorized
            return
          end

          unless user.has_password?
            render json: {
              authenticated: false,
              error: "User does not have password authentication enabled"
            }, status: :unauthorized
            return
          end

          unless user.can_authenticate?
            render json: {
              authenticated: false,
              error: "User account is not active",
              status: user.status
            }, status: :unauthorized
            return
          end

          if user.authenticate(password)
            render json: {
              authenticated: true,
              pd_id: user.pd_id,
              public_id: user.public_id,
              email: user.email,
              access_level: user.access_level
            }
          else
            render json: { authenticated: false }, status: :unauthorized
          end
        end

        private

        def check_identity_api_enabled!
          return if Flipper.enabled?(:identity_api_enabled)

          render json: { error: "Identity API is not enabled" }, status: :service_unavailable
        end
      end
    end
  end
end
