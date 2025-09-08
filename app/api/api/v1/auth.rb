# frozen_string_literal: true

module API
  module V1
    class Auth < Grape::API
      resource :auth do
        desc 'Authenticate user',
          success: { code: 200, message: 'Authentication successful or magic link sent' },
          failure: [
            { code: 400, message: 'Validation failed' },
            { code: 401, message: 'Authentication failed' }
          ],
          tags: ['Authentication'],
          notes: 'Authenticate with email (sends magic link) or magic link token'

        params do
          optional :email, type: String, desc: 'User email address for magic link'
          optional :magic_link_token, type: String, desc: 'Magic link token for authentication'
          
          exactly_one_of :email, :magic_link_token
        end

        post :authenticate do
          if params[:magic_link_token].present?
            authenticate_with_magic_link(params[:magic_link_token])
          else
            send_magic_link(params[:email])
          end
        end
      end

      helpers do
        def authenticate_with_magic_link(token)
          user = User.find_by(magic_link_token: token)
          
          error!("Invalid or expired magic link", 401) if user.nil? || !user.magic_link_valid?

          if user.consume_magic_link_token!
            session_data = {
              user_id: user.id,
              email: user.email,
              access_level: user.access_level,
              authenticated_at: Time.current.iso8601
            }

            success_response({
              message: "Authentication successful",
              user: present(user, with: Entities::User),
              session: session_data
            })
          else
            error!("Failed to process magic link", 500)
          end
        end

        def send_magic_link(email)
          sanitized_email = email.to_s.strip.downcase
          error!("Email is required", 400) if sanitized_email.blank?

          user = User.find_by(email: sanitized_email)

          # Don't reveal whether email exists for security
          if user.nil?
            success_response({
              message: "If an account with this email exists, a magic link has been sent."
            })
          elsif user.send_magic_link
            success_response({
              message: "Magic link sent to your email",
              expires_in: "15 minutes"
            })
          else
            error!("Failed to send magic link", 500)
          end
        end
      end
    end
  end
end