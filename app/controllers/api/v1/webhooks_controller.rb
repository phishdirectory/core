# frozen_string_literal: true

module Api
  module V1
    class WebhooksController < BaseController
      # Require service authentication for webhook management
      before_action :require_service!

      # GET /api/v1/webhooks
      def index
        webhooks = current_service.webhooks.order(created_at: :desc)

        render json: {
          webhooks: webhooks.map { |w| serialize_webhook(w) },
          count: webhooks.size
        }
      end

      # POST /api/v1/webhooks
      def create
        webhook = current_service.webhooks.new(webhook_params)

        if webhook.save
          render json: {
            webhook: serialize_webhook(webhook),
            secret: webhook.secret # Only returned on create
          }, status: :created
        else
          render json: {
            error: "Validation failed",
            details: webhook.errors.full_messages
          }, status: :unprocessable_entity
        end
      end

      # DELETE /api/v1/webhooks/:id
      def destroy
        webhook = current_service.webhooks.find(params[:id])
        webhook.destroy

        render json: { success: true }
      end

      private

      def webhook_params
        params.permit(:url)
      end

      def serialize_webhook(webhook)
        {
          id: webhook.id,
          url: webhook.url,
          active: webhook.active?,
          created_at: webhook.created_at.iso8601
        }
      end
    end
  end
end
