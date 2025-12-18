# frozen_string_literal: true

require "test_helper"

class ApiRequestTest < ActiveSupport::TestCase
  setup do
    @user = create_test_user
    @api_key = @user.user_api_keys.create!(name: "Test Key")
  end

  test "creates api request with valid attributes" do
    request = ApiRequest.create!(
      authenticatable: @api_key,
      user: @user,
      request_path: "/api/v1/domain/check",
      request_method: "GET",
      ip_address: "127.0.0.1",
      user_agent: "TestClient/1.0.0",
      response_code: 200,
      duration_ms: 50,
      requested_at: Time.current
    )

    assert request.persisted?
    assert_equal @api_key, request.authenticatable
    assert_equal @user, request.user
  end

  test "validates presence of required fields" do
    request = ApiRequest.new

    assert_not request.valid?
    assert_includes request.errors[:request_path], "can't be blank"
    assert_includes request.errors[:request_method], "can't be blank"
    assert_includes request.errors[:requested_at], "can't be blank"
  end

  test "success? returns true for 2xx status codes" do
    request = ApiRequest.new(response_code: 200)
    assert request.success?

    request.response_code = 201
    assert request.success?

    request.response_code = 299
    assert request.success?

    request.response_code = 400
    assert_not request.success?
  end

  test "client_error? returns true for 4xx status codes" do
    request = ApiRequest.new(response_code: 400)
    assert request.client_error?

    request.response_code = 404
    assert request.client_error?

    request.response_code = 500
    assert_not request.client_error?
  end

  test "server_error? returns true for 5xx status codes" do
    request = ApiRequest.new(response_code: 500)
    assert request.server_error?

    request.response_code = 503
    assert request.server_error?

    request.response_code = 400
    assert_not request.server_error?
  end

  test "slow? returns true for requests exceeding threshold" do
    request = ApiRequest.new(duration_ms: 1500)
    assert request.slow?
    assert request.slow?(1000)
    assert_not request.slow?(2000)
  end

  test "user_api_key? returns true for user API key authenticatable" do
    request = ApiRequest.new(authenticatable: @api_key)
    assert request.user_api_key?
    assert_not request.service_key?
  end

  test "scopes filter correctly" do
    # Create some test requests
    3.times do |i|
      ApiRequest.create!(
        authenticatable: @api_key,
        request_path: "/api/v1/test",
        request_method: "GET",
        response_code: 200,
        duration_ms: 50 + i,
        requested_at: i.hours.ago
      )
    end

    ApiRequest.create!(
      authenticatable: @api_key,
      request_path: "/api/v1/test",
      request_method: "GET",
      response_code: 500,
      duration_ms: 50,
      requested_at: Time.current
    )

    assert_equal 3, ApiRequest.successful.count
    assert_equal 1, ApiRequest.server_errors.count
    assert_equal 4, ApiRequest.for_user_keys.count
    assert_equal 4, ApiRequest.today.count
  end

  test "parsed_request_headers returns hash from JSON" do
    headers = { "content-type" => "application/json" }
    request = ApiRequest.new(request_headers: headers.to_json)

    assert_equal headers, request.parsed_request_headers
  end

  test "parsed_request_headers returns empty hash for invalid JSON" do
    request = ApiRequest.new(request_headers: "not json")

    assert_equal({}, request.parsed_request_headers)
  end
end
