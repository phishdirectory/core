# frozen_string_literal: true

module Api
  module V1
    module User
      class UsersController < BaseController
        # Require user authentication (not service)
        before_action :require_user!

        # GET /api/v1/user/me
        def me
          render json: {
            user: serialize_user(current_user)
          }
        end

        # PUT /api/v1/user/me
        def update
          if current_user.update(user_params)
            render json: {
              user: serialize_user(current_user)
            }
          else
            render json: {
              error: "Validation failed",
              details: current_user.errors.full_messages
            }, status: :unprocessable_entity
          end
        end

        private

        def user_params
          params.permit(:first_name, :last_name)
        end

        def serialize_user(user)
          {
            id: user.id,
            email: user.email,
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            full_name: user.full_name,
            access_level: user.access_level,
            status: user.status,
            created_at: user.created_at.iso8601,
            updated_at: user.updated_at.iso8601
          }
        end
      end
    end
  end
end
