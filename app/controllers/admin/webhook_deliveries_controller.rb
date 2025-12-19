# frozen_string_literal: true

module Admin
  class WebhookDeliveriesController < BaseController
    before_action :set_delivery, only: [:show, :retry]

    def index
      @deliveries = WebhookDelivery.order(created_at: :desc)

      # Status filter
      if params[:status].present? && WebhookDelivery::STATUSES.include?(params[:status])
        @deliveries = @deliveries.where(status: params[:status])
      end

      # Event filter
      if params[:event].present?
        @deliveries = @deliveries.where(event: params[:event])
      end

      # Retryable filter
      if params[:retryable] == "true"
        @deliveries = @deliveries.retryable
      end

      @deliveries = @deliveries.page(params[:page])
    end

    def show
    end

    def retry
      if @delivery.retryable?
        @delivery.retry_later!
        redirect_to admin_webhook_delivery_path(@delivery), notice: "Delivery queued for retry."
      else
        redirect_to admin_webhook_delivery_path(@delivery), alert: "This delivery cannot be retried."
      end
    end

    private

    def set_delivery
      @delivery = WebhookDelivery.find(params[:id])
    end
  end
end
