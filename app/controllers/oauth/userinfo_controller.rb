# frozen_string_literal: true

module Oauth
  class UserinfoController < ActionController::API
    before_action :doorkeeper_authorize!

    # GET /oauth/userinfo
    # OpenID Connect UserInfo endpoint (RFC 7662)
    def show
      user = User.find(doorkeeper_token.resource_owner_id)
      scopes = doorkeeper_token.scopes

      response = { sub: user.pd_id }

      # Profile scope - basic identity info
      if scopes.include?("profile") || scopes.include?("read")
        response.merge!(profile_claims(user))
      end

      # Email scope
      if scopes.include?("email") || scopes.include?("read")
        response.merge!(email_claims(user))
      end

      # Admin scope - admin/staff info
      if scopes.include?("admin")
        response.merge!(admin_claims(user))
      end

      render json: response
    end

    private

    def profile_claims(user)
      {
        name: user.full_name,
        given_name: user.first_name,
        family_name: user.last_name,
        preferred_username: user.username,
        picture: public_avatar_url(user),
        updated_at: user.updated_at.to_i
      }
    end

    def email_claims(user)
      {
        email: user.email,
        email_verified: user.email_verified?
      }
    end

    def admin_claims(user)
      {
        admin: user.admin?,
        superadmin: user.superadmin?,
        owner: user.owner?,
        staff: user.staff?,
        pd_dev: user.pd_dev?,
        access_level: user.access_level
      }
    end

    def public_avatar_url(user)
      return nil unless user.has_profile_photo?

      Rails.application.routes.url_helpers.user_avatar_url(pd_id: user.pd_id, host: default_url_options[:host])
    rescue StandardError
      nil
    end

    def default_url_options
      Rails.application.config.action_mailer.default_url_options || { host: "phish.directory" }
    end
  end
end
