# frozen_string_literal: true

require "test_helper"

class WebhookTest < ActionDispatch::IntegrationTest
  setup do
    @service = create_test_service
    @key = @service.keys.create!(status: :active)
    @headers = api_headers(api_key: @key.api_key)
  end

  test "service can list webhooks" do
    @service.webhooks.create!(url: "https://example.com/webhook1")
    @service.webhooks.create!(url: "https://example.com/webhook2")

    get api_v1_webhooks_path, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal 2, json["count"]
    assert_equal 2, json["webhooks"].length
  end

  test "service can create webhook" do
    post api_v1_webhooks_path,
         params: { url: "https://example.com/new-webhook" }.to_json,
         headers: @headers

    assert_response :created
    json = JSON.parse(response.body)
    assert_equal "https://example.com/new-webhook", json["webhook"]["url"]
    assert json["secret"].present? # Secret only returned on create
  end

  test "service can delete webhook" do
    webhook = @service.webhooks.create!(url: "https://example.com/webhook")

    delete api_v1_webhook_path(webhook), headers: @headers

    assert_response :success
    assert_nil Service::Webhook.find_by(id: webhook.id)
  end

  test "service cannot manage other service webhooks" do
    other_service = create_test_service
    webhook = other_service.webhooks.create!(url: "https://other.com/webhook")

    delete api_v1_webhook_path(webhook), headers: @headers

    assert_response :not_found
  end

  test "user API key cannot manage webhooks" do
    user = create_test_user
    user_key = user.user_api_keys.create!(name: "Test")
    user_headers = api_headers(api_key: user_key.plaintext_key)

    get api_v1_webhooks_path, headers: user_headers

    assert_response :unauthorized
    json = JSON.parse(response.body)
    assert_match(/service/i, json["error"])
  end
end
