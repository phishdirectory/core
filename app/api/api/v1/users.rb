# frozen_string_literal: true

module API
  module V1
    class Users < Grape::API
      before { authenticate! unless request.path.include?('/users') && request.post? }
      
      resource :users do
        desc 'Create a new user',
          success: [
            { code: 201, message: 'User created successfully', model: Entities::User }
          ],
          failure: [
            { code: 422, message: 'Validation failed' },
            { code: 401, message: 'Authentication required' }
          ],
          tags: ['Users'],
          notes: 'Create a new user account. A magic link will be sent for email verification.'

        params do
          requires :first_name, type: String, desc: 'User first name', example: 'John'
          requires :last_name, type: String, desc: 'User last name', example: 'Doe'
          requires :email, type: String, desc: 'User email address', example: 'john@example.com'
        end

        post do
          user_params_hash = {
            first_name: params[:first_name],
            last_name: params[:last_name],
            email: params[:email].strip.downcase
          }

          user = User.new(user_params_hash)

          if user.save
            # Send magic link for first login
            user.send_magic_link

            status 201
            success_response({
              message: "User created successfully. A magic link has been sent to complete setup.",
              user: present(user, with: Entities::User)
            })
          else
            error!("Failed to create user", 422)
          end
        end

        desc 'Get user by ID',
          success: [
            { code: 200, message: 'User information', model: Entities::User }
          ],
          failure: [
            { code: 404, message: 'User not found' },
            { code: 401, message: 'Authentication required' }
          ],
          tags: ['Users'],
          notes: 'Retrieve user information by Phish Directory ID'

        params do
          requires :id, type: String, desc: 'Phish Directory user ID', example: 'PDU1ABC2DEF'
        end

        get ':id' do
          user = User.find_by!(pd_id: params[:id])
          success_response(present(user, with: Entities::User))
        end

        desc 'Get user by email',
          success: [
            { code: 200, message: 'User information', model: Entities::User }
          ],
          failure: [
            { code: 404, message: 'User not found' },
            { code: 401, message: 'Authentication required' }
          ],
          tags: ['Users'],
          notes: 'Retrieve user information by email address'

        params do
          requires :email, type: String, desc: 'User email address', example: 'user@example.com'
        end

        get 'by_email/:email' do
          user = User.find_by!(email: params[:email].downcase.strip)
          success_response(present(user, with: Entities::User))
        end

        desc 'Get current user information',
          success: [
            { code: 200, message: 'Current user information', model: Entities::User }
          ],
          failure: [
            { code: 401, message: 'Authentication required' }
          ],
          tags: ['Users'],
          notes: 'Retrieve information about the currently authenticated user'

        get :me do
          success_response(present(current_user, with: Entities::User))
        end
      end
    end
  end
end