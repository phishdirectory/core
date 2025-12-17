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
        webhook = find_webhook(params[:id])
        webhook.discard  # Use soft delete

        render json: { success: true }
      end

      private

      def webhook_params
        params.permit(:url)
      end

      def find_webhook(id)
        # Support both public_id format (swh_xxx) and legacy UUID
        # Scoped to current service for security
        if id.to_s.start_with?("swh_")
          current_service.service_webhooks.find_by_public_id!(id)
        else
          current_service.service_webhooks.find(id)
        end
      end

      def serialize_webhook(webhook)
        {
          id: webhook.public_id,
          url: webhook.url,
          active: webhook.active?,
          created_at: webhook.created_at.iso8601
        }
      end
    end
  end
end
