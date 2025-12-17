# frozen_string_literal: true

module Admin
  class ServiceWebhooksController < BaseController
    before_action :set_service
    before_action :set_webhook, only: [:destroy]

    def index
      @webhooks = @service.service_webhooks
    end

    def create
      @webhook = @service.register_webhook!(url: params[:url])
      redirect_to admin_service_path(@service), notice: "Webhook registered. Secret: #{@webhook.secret}"
    rescue ActiveRecord::RecordInvalid => e
      redirect_to admin_service_path(@service), alert: "Failed to register webhook: #{e.message}"
    end

    def destroy
      @webhook.destroy
      redirect_to admin_service_path(@service), notice: "Webhook deleted."
    end

    private

    def set_service
      @service = Service.find_by_public_id!(params[:service_id])
    end

    def set_webhook
      @webhook = @service.service_webhooks.find(params[:id])
    end
  end
end
