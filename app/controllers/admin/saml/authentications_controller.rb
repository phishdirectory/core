# frozen_string_literal: true

module Admin
  module Saml
    class AuthenticationsController < BaseController
      def index
        @authentications = ::Saml::Authentication
          .includes(:user, :service_provider)
          .order(created_at: :desc)
          .page(params[:page])

        # Optional filters
        @authentications = @authentications.for_user(User.find_by_public_id(params[:user_id])) if params[:user_id].present?
        @authentications = @authentications.for_service_provider(::Saml::ServiceProvider.find_by_public_id(params[:service_provider_id])) if params[:service_provider_id].present?
        @authentications = @authentications.where(status: params[:status]) if params[:status].present?
      end

      def show
        @authentication = ::Saml::Authentication.find(params[:id])
      end
    end
  end
end
