# frozen_string_literal: true

module Api
  module V1
    module Identity
      class UsersController < BaseController
        before_action :require_service!
        before_action :check_identity_api_enabled!
        before_action :set_user, only: [:show, :update]

        # GET /api/v1/identity/users/:id
        def show
          render json: serialize_user(@user)
        end

        # GET /api/v1/identity/users/by_email?email=...
        def by_email
          email = params[:email]&.strip&.downcase

          if email.blank?
            render json: { error: "Email parameter is required" }, status: :bad_request
            return
          end

          user = User.find_by(email: email)

          if user.nil?
            render json: { error: "User not found" }, status: :not_found
            return
          end

          render json: serialize_user(user)
        end

        # POST /api/v1/identity/users
        def create
          user_data = user_params

          # Check if email already exists
          if User.exists?(email: user_data[:email]&.downcase)
            render json: { error: "Email already exists" }, status: :unprocessable_entity
            return
          end

          user = User.new(user_data)
          user.email_verified = true if params[:skip_confirmation]

          if user.save
            WebhookService.notify_user_created(user.pd_id, user.email)
            render json: serialize_user(user), status: :created
          else
            render json: { error: user.errors.full_messages.to_sentence }, status: :unprocessable_entity
          end
        end

        # PUT /api/v1/identity/users/:id
        def update
          if @user.update(update_params)
            WebhookService.notify_user_updated(@user.pd_id)
            render json: serialize_user(@user)
          else
            render json: { error: @user.errors.full_messages.to_sentence }, status: :unprocessable_entity
          end
        end

        private

        def check_identity_api_enabled!
          return if Flipper.enabled?(:identity_api_enabled)

          render json: { error: "Identity API is not enabled" }, status: :service_unavailable
        end

        def set_user
          @user = find_user_by_identifier(params[:id])
        end

        def find_user_by_identifier(id)
          if id.to_s.start_with?("PDU")
            User.find_by!(pd_id: id)
          elsif id.to_s.start_with?("usr_")
            User.find_by_public_id!(id)
          else
            User.find(id)
          end
        end

        def user_params
          params.permit(:email, :first_name, :last_name, :password, :password_confirmation)
        end

        def update_params
          params.permit(:first_name, :last_name)
        end

        def serialize_user(user)
          {
            pd_id: user.pd_id,
            public_id: user.public_id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            full_name: user.full_name,
            username: user.username,
            status: user.status,
            access_level: user.access_level,
            staff: user.staff?,
            pd_dev: user.pd_dev?,
            email_verified: user.email_verified?,
            has_password: user.has_password?,
            locked_at: user.locked_at,
            created_at: user.created_at.iso8601,
            updated_at: user.updated_at.iso8601
          }
        end
      end
    end
  end
end
