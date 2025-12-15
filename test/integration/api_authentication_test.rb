# frozen_string_literal: true

require "test_helper"

class ApiAuthenticationTest < ActionDispatch::IntegrationTest
  test "health endpoint requires no authentication" do
    get api_v1_health_path, headers: api_headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "ok", json["status"]
    assert json["timestamp"].present?
  end

  test "user endpoint requires authentication" do
    get api_v1_user_me_path, headers: api_headers

    assert_response :unauthorized
    json = JSON.parse(response.body)
    assert json["error"].present?
  end

  test "user can authenticate with API key" do
    user = create_test_user
    api_key = user.user_api_keys.create!(name: "Test Key")
    plaintext_key = api_key.plaintext_key

    get api_v1_user_me_path, headers: api_headers(api_key: plaintext_key)

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal user.email, json["user"]["email"]
  end

  test "invalid API key is rejected" do
    get api_v1_user_me_path, headers: api_headers(api_key: "pdat_invalid_key")

    assert_response :unauthorized
  end

  test "service can authenticate with service key" do
    service = create_test_service
    key = service.keys.create!(status: :active)

    post api_v1_auth_authenticate_path,
         headers: api_headers(api_key: key.api_key)

    assert_response :success
    json = JSON.parse(response.body)
    assert json["authenticated"]
    assert_equal service.name, json["service"]["name"]
  end

  test "revoked service key is rejected" do
    service = create_test_service
    key = service.keys.create!(status: :revoked)

    post api_v1_auth_authenticate_path,
         headers: api_headers(api_key: key.api_key)

    assert_response :unauthorized
  end

  test "API key can be passed via X-API-Key header" do
    user = create_test_user
    api_key = user.user_api_keys.create!(name: "Test Key")

    get api_v1_user_me_path,
        headers: { "X-API-Key" => api_key.plaintext_key, "Accept" => "application/json" }

    assert_response :success
  end
end
