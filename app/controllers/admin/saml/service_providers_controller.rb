# frozen_string_literal: true

module Admin
  module Saml
    class ServiceProvidersController < BaseController
      before_action :set_service_provider, except: [ :index, :new, :create ]

      def index
        @service_providers = ::Saml::ServiceProvider.with_discarded.order(created_at: :desc).page(params[:page])
      end

      def show
        @authentications = @service_provider.authentications.recent
      end

      def new
        @service_provider = ::Saml::ServiceProvider.new
        @services = Service.active.order(:name)
      end

      def create
        @service_provider = ::Saml::ServiceProvider.new(service_provider_params)

        if @service_provider.save
          redirect_to admin_saml_service_provider_path(@service_provider),
                      notice: "SAML Service Provider created successfully."
        else
          @services = Service.active.order(:name)
          render :new, status: :unprocessable_entity
        end
      end

      def edit
        @services = Service.active.order(:name)
      end

      def update
        if @service_provider.update(service_provider_params)
          redirect_to admin_saml_service_provider_path(@service_provider),
                      notice: "SAML Service Provider updated successfully."
        else
          @services = Service.active.order(:name)
          render :edit, status: :unprocessable_entity
        end
      end

      def destroy
        @service_provider.discard!
        redirect_to admin_saml_service_providers_path,
                    notice: "SAML Service Provider removed."
      end

      def enable
        @service_provider.update!(enabled: true)
        redirect_to admin_saml_service_provider_path(@service_provider),
                    notice: "SAML Service Provider enabled."
      end

      def disable
        @service_provider.update!(enabled: false)
        redirect_to admin_saml_service_provider_path(@service_provider),
                    notice: "SAML Service Provider disabled."
      end

      private

      def set_service_provider
        @service_provider = ::Saml::ServiceProvider.with_discarded.find_by_public_id!(params[:id])
      end

      def service_provider_params
        params.require(:saml_service_provider).permit(
          :name,
          :entity_id,
          :assertion_consumer_service_url,
          :single_logout_service_url,
          :metadata_url,
          :certificate,
          :name_id_format,
          :authn_context_class_ref,
          :sign_assertions,
          :encrypt_assertions,
          :enabled,
          :service_id,
          attribute_statement: {}
        )
      end
    end
  end
end
