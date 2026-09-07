# frozen_string_literal: true

require "test_helper"

class DeliverWebhookJobTest < ActiveJob::TestCase
  setup do
    @secret = SecureRandom.hex(32)
    @delivery = WebhookDelivery.create!(
      url: "https://hooks.example.com/notify",
      event: "domain.verdict",
      payload: { domain: "bad.com" }.to_json,
      status: "pending"
    )
  end

  test "signs the timestamp alongside the body" do
    stub_request(:post, @delivery.url).to_return(status: 200, body: "ok")

    DeliverWebhookJob.perform_now(@delivery, @secret)

    assert_requested(:post, @delivery.url) do |req|
      timestamp = req.headers["X-Webhook-Timestamp"]
      signature = req.headers["X-Webhook-Signature"]
      expected = OpenSSL::HMAC.hexdigest("SHA256", @secret, "#{timestamp}.#{@delivery.payload}")

      timestamp.present? && signature == expected
    end
  end

  test "sets connect and read timeouts so a hung endpoint cannot pin a worker" do
    stub_request(:post, @delivery.url).to_timeout

    DeliverWebhookJob.perform_now(@delivery, @secret)

    assert_equal "failed", @delivery.reload.status
  end

  test "records a delivered response" do
    stub_request(:post, @delivery.url).to_return(status: 200, body: "thanks")

    DeliverWebhookJob.perform_now(@delivery, @secret)

    assert_equal "delivered", @delivery.reload.status
  end

  test "a rejected response is marked failed" do
    stub_request(:post, @delivery.url).to_return(status: 500, body: "nope")

    DeliverWebhookJob.perform_now(@delivery, @secret)

    assert_equal "failed", @delivery.reload.status
  end

  test "refuses to call an internal address and never makes the request" do
    internal = WebhookDelivery.create!(
      url: "http://169.254.169.254/latest/meta-data/",
      event: "domain.verdict",
      payload: "{}",
      status: "pending"
    )

    DeliverWebhookJob.perform_now(internal, @secret)

    assert_equal "failed", internal.reload.status
    assert_not_requested :post, "http://169.254.169.254/latest/meta-data/"
  end

  test "omits the signature headers when there is no secret" do
    stub_request(:post, @delivery.url).to_return(status: 200)

    DeliverWebhookJob.perform_now(@delivery, nil)

    assert_requested(:post, @delivery.url) do |req|
      req.headers["X-Webhook-Signature"].nil? && req.headers["X-Webhook-Timestamp"].nil?
    end
  end
end
