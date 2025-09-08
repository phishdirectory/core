# frozen_string_literal: true

module Api
  module V1
    class UsersController < BaseController
      def me
        render_success(user_data(current_user))
      end

      def show
        user = find_user
        return unless user

        render_success(user_data(user))
      end

      def create
        user_params_hash = user_params
        user = User.new(user_params_hash)

        if user.save
          # Send magic link for first login
          user.send_magic_link

          render_success({
            message: "User created successfully. A magic link has been sent to complete setup.",
            user: user_data(user)
          }, :created)
        else
          render_error(
            "Failed to create user",
            :unprocessable_entity,
            user.errors.full_messages
          )
        end
      end

      private

      def find_user
        if params[:email].present?
          user = User.find_by(email: params[:email].downcase.strip)
          
          unless user
            render_error("User not found", :not_found)
            return nil
          end
        elsif params[:id].present?
          user = User.find_by(pd_id: params[:id])
          
          unless user
            render_error("User not found", :not_found)
            return nil
          end
        else
          render_error("User ID or email required", :bad_request)
          return nil
        end

        user
      end

      def user_data(user)
        {
          id: user.id,
          pd_id: user.pd_id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          full_name: user.full_name,
          username: user.username,
          email_verified: user.email_verified?,
          access_level: user.access_level,
          staff: user.staff?,
          status: user.status,
          created_at: user.created_at.iso8601,
          updated_at: user.updated_at.iso8601,
          profile_photo_url: user.has_profile_photo? ? user.public_avatar_url : nil
        }
      end

      def user_params
        permitted_params = params.require(:user).permit(
          :first_name, 
          :last_name, 
          :email
        )

        # Sanitize email
        if permitted_params[:email].present?
          permitted_params[:email] = permitted_params[:email].strip.downcase
        end

        permitted_params
      end
    end
  end
end