# frozen_string_literal: true

module Api
  module V1
    class AuthController < BaseController
      skip_before_action :authenticate_api_request!, only: [:authenticate]

      def authenticate
        email = params[:email]
        magic_link_token = params[:magic_link_token]

        if email.blank? && magic_link_token.blank?
          render_error("Email or magic link token required", :bad_request)
          return
        end

        if magic_link_token.present?
          authenticate_with_magic_link(magic_link_token)
        else
          send_magic_link(email)
        end
      end

      private

      def authenticate_with_magic_link(token)
        user = User.find_by(magic_link_token: token)
        
        if user.nil? || !user.magic_link_valid?
          render_error("Invalid or expired magic link", :unauthorized)
          return
        end

        if user.consume_magic_link_token!
          # Generate API session token for this user (you may want to implement JWT or similar)
          session_data = {
            user_id: user.id,
            email: user.email,
            access_level: user.access_level,
            authenticated_at: Time.current.iso8601
          }

          render_success({
            message: "Authentication successful",
            user: user_data(user),
            session: session_data
          })
        else
          render_error("Failed to process magic link", :internal_server_error)
        end
      end

      def send_magic_link(email)
        begin
          sanitized_email = email.to_s.strip.downcase
        rescue
          render_error("Invalid email format", :bad_request)
          return
        end

        if sanitized_email.blank?
          render_error("Email is required", :bad_request)
          return
        end

        user = User.find_by(email: sanitized_email)

        # Don't reveal whether email exists for security
        if user.nil?
          render_success({
            message: "If an account with this email exists, a magic link has been sent."
          })
          return
        end

        if user.send_magic_link
          render_success({
            message: "Magic link sent to your email",
            expires_in: "15 minutes"
          })
        else
          render_error("Failed to send magic link", :internal_server_error)
        end
      end

      def user_data(user)
        {
          id: user.id,
          pd_id: user.pd_id,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          username: user.username,
          email_verified: user.email_verified?,
          access_level: user.access_level,
          created_at: user.created_at.iso8601
        }
      end
    end
  end
end