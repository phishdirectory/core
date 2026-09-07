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

          # ::User, not User. Constant lookup walks the lexical scope and
          # finds the Api::V1::User module (the namespace of the /user
          # endpoints) before it reaches the model. With eager loading that
          # module is always defined, so the unqualified form raised
          # NoMethodError on every call in production.
          user = ::User.find_by(email: email)

          # One answer for every way this can fail. Distinguishing "no such
          # user" from "no password set" from "not active" let any service key
          # enumerate the user base and read account state.
          unless user&.has_password? && user.can_authenticate? && user.authenticate(password)
            return render json: { authenticated: false }, status: :unauthorized
          end

          render json: {
            authenticated: true,
            pd_id: user.pd_id,
            public_id: user.public_id,
            email: user.email,
            access_level: user.access_level
          }
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
