# frozen_string_literal: true

module Api
  class V1 < Grape::API
    version "v1", using: :path
    prefix :api
    format :json
    default_format :json


    # desc "Flavor text!" do
    #   summary "Flavor text!"
    #   failure [[404]]
    #   hidden true
    # end
    # get :flavor do
    #   {
    #     flavor: FlavorTextService.new.generate
    #   }
    # end


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
    )

  end
end
