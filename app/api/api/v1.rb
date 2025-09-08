# frozen_string_literal: true

module Api
  class V1 < Grape::API
    include Grape::Kaminari

    version "v1", using: :path
    prefix :api
    format :json
    default_format :json

    helpers do
      def users
        @users ||= paginate(User.all.order(created_at: :desc))
      end

      def authenticate!
        api_key_value = extract_api_key
        error!({ message: "API key required" }, 401) unless api_key_value
        
        api_key = UserApiKey.find_by_key(api_key_value)
        error!({ message: "Invalid API key" }, 401) unless api_key&.api_valid?
        
        api_key.touch_last_used!
        @current_user = api_key.user
      end

      def current_user
        @current_user
      end

      private

      def extract_api_key
        # Support both X-API-Key header and Authorization: Bearer format
        headers["X-API-Key"] || bearer_token
      end

      def bearer_token
        auth_header&.match(/\ABearer (.+)\z/)&.[](1)
      end

      def auth_header
        headers["Authorization"]
      end
    end

    desc "Healthcheck" do
      summary "Helthcheck endpoint"
      failure [[404]]
      hidden false
    end
    get :healthcheck do
      { status: "ok", timestamp: Time.current.iso8601 }
    end

    resource :user do
      desc "Get current user info" do
        summary "Get information about the authenticated user"
        tags ["User"]
        security [{ api_key: [] }]
        success Entities::User
        failure [[401, "Unauthorized"]]
        failure [[403, "Forbidden"]]
      end
      get :me do
        authenticate!
        present current_user, with: Entities::User
      end
    end


    # Handle validation errors
    rescue_from Grape::Exceptions::ValidationErrors do |e|
      error!({ message: e.message }, 400)
    end

    # Handle 404 errors (catch all)
    route :any, "*path" do
      error!({ message: "Path not found. Please see the documentation (https://phish.directory/docs/api/v1/) for all available paths." }, 404)
    end

    # Handle unexpected errors
    rescue_from ActiveRecord::RecordNotFound do
      error!({ message: "Not found." }, 404)
    end
    rescue_from Pundit::NotAuthorizedError do
      error!({ message: "Not authorized." }, 403)
    end
    rescue_from :all do |e|
      Rails.error.report(e, handled: false, severity: :error, context: "api")

      # Provide error message in api response ONLY in development mode
      msg = if Rails.env.development?
              e.message
            else
              "A server error has occurred."
            end
      error!({ message: msg }, 500)
    end

    add_swagger_documentation(
      openapi: "3.0.0",
      info: {
        title: "Phish Directory API",
        description: "API for phish.directory, a community-driven anti-phishing tool. Helping catch, prevent, and catalog phishing links & attempts",
        contact_name: "phish.directory",
        contact_email: "team@phish.directory",
      },
      doc_version: "1.0.0",
      models: [
        Entities::User
      ],
      array_use_braces: true,
      tags: [
        { name: "Domain", description: "Domain-related operations" },
        { name: "Email", description: "Email-related operations" },
        { name: "User", description: "User management operations" },
      ],
      security_definitions: {
        api_key: {
          type: "apiKey",
          name: "X-API-Key",
          in: "header",
          description: "API key for authentication using X-API-Key header"
        },
        bearer_auth: {
          type: "apiKey",
          name: "Authorization",
          in: "header",
          description: "API key for authentication. Format: Bearer YOUR_API_KEY"
        }
      },
    )

  end
end
