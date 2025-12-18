# frozen_string_literal: true

require "test_helper"

class UserAgentRequirementTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
    @api_key = @user.user_api_keys.create!(name: "Test Key")
  end

  test "authenticated request without User-Agent returns 400" do
    headers = {
      "Content-Type" => "application/json",
      "Accept" => "application/json",
      "Authorization" => "Bearer #{@api_key.plaintext_key}"
    }

    get api_v1_user_me_path, headers: headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_equal "User-Agent header is required", json["error"]
    assert json["hint"].present?
  end

  test "authenticated request with User-Agent succeeds" do
    get api_v1_user_me_path, headers: api_headers(api_key: @api_key.plaintext_key)

    assert_response :success
  end

  test "health endpoint does not require User-Agent" do
    headers = {
      "Content-Type" => "application/json",
      "Accept" => "application/json"
    }

    get api_v1_health_path, headers: headers

    assert_response :success
  end

  test "unauthenticated request fails before User-Agent check" do
    headers = {
      "Content-Type" => "application/json",
      "Accept" => "application/json"
    }

    get api_v1_user_me_path, headers: headers

    # Should fail with 401 Unauthorized (auth check happens before User-Agent check)
    assert_response :unauthorized
  end
end
