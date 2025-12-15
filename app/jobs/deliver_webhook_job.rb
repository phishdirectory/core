# frozen_string_literal: true

class DeliverWebhookJob < ApplicationJob
  queue_as :webhooks

  retry_on StandardError, wait: :polynomially_longer, attempts: 5

  def perform(delivery, secret = nil)
    delivery.mark_delivering!

    response = Faraday.post(delivery.url) do |req|
      req.headers["Content-Type"] = "application/json"
      req.headers["X-Webhook-Event"] = delivery.event
      req.headers["X-Webhook-Signature"] = sign_payload(delivery.payload, secret) if secret
      req.body = delivery.payload
    end

    if response.success?
      delivery.mark_delivered!(
        status: response.status,
        headers: response.headers.to_h,
        body: response.body.truncate(10_000)
      )
    else
      delivery.mark_failed!(
        status: response.status,
        headers: response.headers.to_h,
        body: response.body.truncate(10_000)
      )
      delivery.retry_later! if delivery.retryable?
    end
  rescue Faraday::Error => e
    delivery.mark_failed!(error: e.message)
    delivery.retry_later! if delivery.retryable?
  end

  private

  def sign_payload(payload, secret)
    return nil unless secret

    OpenSSL::HMAC.hexdigest("SHA256", secret, payload)
  end
end
