# frozen_string_literal: true

require "test_helper"

# Every webhook used to receive every event, for every service. user.created
# carries an email address, so a single registered endpoint saw the email of
# every user who signed up anywhere on the platform.
class WebhookServiceTest < ActiveSupport::TestCase
  setup do
    @service = create_test_service
    @other_service = create_test_service
  end

  def webhook_for(service, events:)
    service.service_webhooks.create!(
      url: "https://hooks.example.com/#{SecureRandom.hex(4)}",
      events: events
    )
  end

  test "an event only reaches endpoints subscribed to it" do
    subscribed = webhook_for(@service, events: [ "domain.verdict" ])
    unsubscribed = webhook_for(@other_service, events: [ "user.created" ])

    domain = Phish::Domain.create!(domain: "bad-#{SecureRandom.hex(4)}.com")
    verdict = Verdict.create!(classification: "phishing", confidence_score: 0.95)

    WebhookService.notify_domain_verdict(domain, verdict)

    assert_equal 1, WebhookDelivery.where(url: subscribed.url).count
    assert_equal 0, WebhookDelivery.where(url: unsubscribed.url).count
  end

  test "a user's email is not broadcast to endpoints that did not ask for it" do
    uninterested = webhook_for(@other_service, events: [ "domain.verdict" ])

    WebhookService.notify_user_created(create_test_user)

    assert_equal 0, WebhookDelivery.where(url: uninterested.url).count
  end

  test "an endpoint subscribed to everything still receives everything" do
    everything = webhook_for(@service, events: Service::Webhook::EVENTS)

    WebhookService.notify_user_created(create_test_user)

    assert_equal 1, WebhookDelivery.where(url: everything.url, event: "user.created").count
  end

  test "broadcasting an event nobody defined is a programming error" do
    assert_raises(ArgumentError) do
      WebhookService.send(:broadcast_event, "totally.made.up", {})
    end
  end

  test "a discarded webhook receives nothing" do
    gone = webhook_for(@service, events: Service::Webhook::EVENTS)
    gone.discard!

    WebhookService.notify_user_created(create_test_user)

    assert_equal 0, WebhookDelivery.where(url: gone.url).count
  end
end
