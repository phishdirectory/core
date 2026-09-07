# frozen_string_literal: true

require "test_helper"

# api_requests is written on the hottest path in the application. These tests
# pin what it stores, because it previously captured plaintext passwords and
# webhook secrets and kept up to 20KB of body on every successful call.
class ApiRequestLoggingTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
    @api_key = @user.user_api_keys.create!(name: "Test Key")
    @headers = api_headers(api_key: @api_key.plaintext_key)
  end

  test "a successful request is logged without any body" do
    get api_v1_domain_check_path, params: { domain: "logged.com" }, headers: @headers

    assert_response :success
    logged = ApiRequest.order(:created_at).last
    assert_equal "/api/v1/domain/check", logged.request_path
    assert_equal 200, logged.response_code
    assert_nil logged.request_body, "successful calls should not retain bodies"
    assert_nil logged.response_body
  end

  test "a failed request retains bodies so the failure can be investigated" do
    get api_v1_domain_check_path, params: { domain: "not a domain" }, headers: @headers

    assert_response :bad_request
    logged = ApiRequest.order(:created_at).last
    assert logged.response_body.present?, "error responses should be retained"
  end

  test "a password in a request body is never written to the database" do
    service = create_test_service
    service_key = service.service_keys.create!
    Flipper.enable(:identity_api)

    post api_v1_identity_authenticate_path,
         params: { email: @user.email, password: "hunter2-should-not-persist" }.to_json,
         headers: api_headers(api_key: service_key.plaintext_key)

    logged = ApiRequest.order(:created_at).last
    assert_not_nil logged
    assert logged.request_body.present?, "the failed call should still be diagnosable"
    assert_no_match(/hunter2-should-not-persist/, logged.request_body)
    assert_no_match(/hunter2-should-not-persist/, logged.response_body.to_s)
    assert_match(/FILTERED/, logged.request_body,
                 "the password should be replaced, not merely absent")
  ensure
    Flipper.disable(:identity_api)
  end

  # We can only pick secrets out of a body we can parse. Anything else is
  # dropped rather than stored on the chance that it holds a credential.
  test "a body we cannot parse as json is dropped rather than stored" do
    post api_v1_domain_check_path,
         params: { domain: "not a domain", password: "hunter2-form-encoded" },
         headers: api_headers(api_key: @api_key.plaintext_key)
           .merge("Content-Type" => "application/x-www-form-urlencoded")

    assert_response :bad_request
    logged = ApiRequest.order(:created_at).last
    assert_no_match(/hunter2-form-encoded/, logged.request_body.to_s)
    assert_equal "[unparseable body omitted]", logged.request_body
  end

  test "last_api_activity_at is not rewritten on every request" do
    get api_v1_domain_check_path, params: { domain: "first.com" }, headers: @headers
    first_touch = @user.reload.last_api_activity_at
    assert first_touch.present?

    get api_v1_domain_check_path, params: { domain: "second.com" }, headers: @headers

    assert_equal first_touch.to_f, @user.reload.last_api_activity_at.to_f,
                 "a second call moments later should not write the users row again"
  end

  test "activity is recorded again once the throttle window has passed" do
    get api_v1_domain_check_path, params: { domain: "first.com" }, headers: @headers
    @user.update!(last_api_activity_at: 10.minutes.ago)
    stale = @user.reload.last_api_activity_at

    get api_v1_domain_check_path, params: { domain: "second.com" }, headers: @headers

    assert @user.reload.last_api_activity_at > stale
  end
end
