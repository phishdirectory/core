# frozen_string_literal: true

require "test_helper"

# The identity endpoint answered differently for "no such user", "no password
# set" and "account not active", and the last one echoed the status back. Any
# holder of a service key could enumerate the user base and read account state.
class IdentityApiTest < ActionDispatch::IntegrationTest
  PASSWORD = "Str0ng-Passw0rd!"

  setup do
    @service = create_test_service
    @key = @service.service_keys.create!
    @headers = api_headers(api_key: @key.plaintext_key)
    Flipper.enable(:identity_api_enabled)
  end

  teardown do
    Flipper.disable(:identity_api_enabled)
  end

  def authenticate(email:, password: PASSWORD)
    post api_v1_identity_authenticate_path,
         params: { email: email, password: password }.to_json,
         headers: @headers
  end

  def user_with_password
    user = create_test_user
    user.update!(password: PASSWORD, password_confirmation: PASSWORD)
    user
  end

  test "correct credentials authenticate" do
    user = user_with_password

    authenticate(email: user.email)

    assert_response :success
    body = JSON.parse(response.body)
    assert body["authenticated"]
    assert_equal user.pd_id, body["pd_id"]
  end

  test "every failure looks identical" do
    with_password = user_with_password
    without_password = create_test_user
    suspended = user_with_password
    suspended.update_column(:status, "suspended")

    responses = [
      -> { authenticate(email: "nobody-#{SecureRandom.hex(4)}@example.com") },
      -> { authenticate(email: without_password.email) },
      -> { authenticate(email: suspended.email) },
      -> { authenticate(email: with_password.email, password: "wrong-password") }
    ].map do |request|
      request.call
      [ response.status, response.body ]
    end

    assert_equal 1, responses.map(&:first).uniq.size,
                 "different statuses let a caller tell these cases apart"
    assert_equal 1, responses.map(&:last).uniq.size,
                 "different bodies enumerate the user base"
  end

  test "a failure never reveals account status" do
    suspended = user_with_password
    suspended.update_column(:status, "suspended")

    authenticate(email: suspended.email)

    assert_response :unauthorized
    assert_no_match(/suspended/i, response.body)
  end

  test "a missing parameter is still a clear client error" do
    post api_v1_identity_authenticate_path,
         params: { email: "someone@example.com" }.to_json,
         headers: @headers

    assert_response :bad_request
  end
end
