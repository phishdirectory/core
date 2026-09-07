# frozen_string_literal: true

class DeliverWebhookJob < ApplicationJob
  queue_as QUEUE_WEBHOOKS

  # Retries are managed through the delivery record's own attempt counter, not
  # ActiveJob. Having both meant a failing endpoint was retried twice over:
  # retry_on re-ran the job while retry_later! enqueued a second one.
  discard_on ActiveJob::DeserializationError

  # A webhook endpoint is someone else's server. Without these a hung endpoint
  # held a worker thread until the process was restarted.
  OPEN_TIMEOUT = 5
  READ_TIMEOUT = 10

  def perform(delivery, secret = nil)
    # Re-check at delivery time, not just at save time: a hostname that was
    # public when the webhook was registered can resolve to a private address
    # later.
    if WebhookAddressPolicy.internal?(delivery.url)
      Rails.logger.warn("[DeliverWebhook] Refusing to deliver to #{delivery.url}: not a public address")
      delivery.mark_failed!(error: "Refused: URL does not resolve to a public address")
      return
    end

    delivery.mark_delivering!

    timestamp = Time.current.to_i
    response = post(delivery, secret, timestamp)

    if response.success?
      delivery.mark_delivered!(
        status: response.status,
        headers: response.headers.to_h,
        body: response.body.to_s.truncate(10_000)
      )
    else
      delivery.mark_failed!(
        status: response.status,
        headers: response.headers.to_h,
        body: response.body.to_s.truncate(10_000)
      )
      delivery.retry_later! if delivery.retryable?
    end
  rescue Faraday::Error => e
    delivery.mark_failed!(error: e.message)
    delivery.retry_later! if delivery.retryable?
  end

  private

  def post(delivery, secret, timestamp)
    Faraday.post(delivery.url) do |req|
      req.options.open_timeout = OPEN_TIMEOUT
      req.options.timeout = READ_TIMEOUT
      req.headers["Content-Type"] = "application/json"
      req.headers["X-Webhook-Event"] = delivery.event
      req.headers["X-Webhook-Delivery"] = delivery.public_id if delivery.respond_to?(:public_id)

      if secret
        req.headers["X-Webhook-Timestamp"] = timestamp.to_s
        req.headers["X-Webhook-Signature"] = sign(delivery.payload, secret, timestamp)
      end

      req.body = delivery.payload
    end
  end

  # The timestamp is signed alongside the body. Signing the body alone made
  # every delivery replayable forever: a captured request stayed valid because
  # nothing in it expired.
  def sign(payload, secret, timestamp)
    OpenSSL::HMAC.hexdigest("SHA256", secret, "#{timestamp}.#{payload}")
  end
end
