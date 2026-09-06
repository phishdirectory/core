# frozen_string_literal: true

require "test_helper"

class EmailCheckTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
    @api_key = @user.user_api_keys.create!(name: "Test Key")
    @headers = api_headers(api_key: @api_key.plaintext_key)
  end

  test "can check an email" do
    get api_v1_email_check_path, params: { email: "test@example.com" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "test@example.com", json["email"]
    assert_equal "example.com", json["domain"]
    assert json["verdict"].present?
    assert json["created_at"].present?
    assert json["id"].start_with?("eml_")
  end

  test "email check normalizes input" do
    get api_v1_email_check_path,
        params: { email: "  TEST@EXAMPLE.COM  " },
        headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "test@example.com", json["email"]
  end

  test "email check extracts domain" do
    get api_v1_email_check_path,
        params: { email: "user@subdomain.example.org" },
        headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "subdomain.example.org", json["domain"]
  end

  test "email check requires email parameter" do
    get api_v1_email_check_path, headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_match(/email/i, json["error"])
  end

  test "email check rejects invalid format" do
    get api_v1_email_check_path,
        params: { email: "not-an-email" },
        headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_match(/invalid/i, json["error"])
  end

  test "can bulk check emails" do
    post api_v1_email_bulk_path,
         params: { emails: [ "user1@example.com", "user2@example.com", "user3@example.com" ] }.to_json,
         headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal 3, json["count"]
    assert_equal 3, json["results"].length
  end

  test "bulk check limits to 100 emails" do
    emails = (1..101).map { |i| "user#{i}@example.com" }

    post api_v1_email_bulk_path,
         params: { emails: emails }.to_json,
         headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_match(/100/, json["error"])
  end

  test "bulk check returns emails in order" do
    emails = [ "first@example.com", "second@example.com", "third@example.com" ]

    post api_v1_email_bulk_path,
         params: { emails: emails }.to_json,
         headers: @headers

    assert_response :success
    json = JSON.parse(response.body)

    assert_equal "first@example.com", json["results"][0]["email"]
    assert_equal "second@example.com", json["results"][1]["email"]
    assert_equal "third@example.com", json["results"][2]["email"]
  end

  test "bulk check deduplicates emails" do
    emails = [ "same@example.com", "same@example.com", "same@example.com" ]

    post api_v1_email_bulk_path,
         params: { emails: emails }.to_json,
         headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal 1, json["count"]
  end

  test "bulk check reports invalid emails" do
    emails = [ "valid@example.com", "invalid", "another@example.com" ]

    post api_v1_email_bulk_path,
         params: { emails: emails }.to_json,
         headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert json["invalid_emails"].present?
    assert_includes json["invalid_emails"], "invalid"
  end

  test "email check requires authentication" do
    get api_v1_email_check_path, params: { email: "test@example.com" }

    assert_response :unauthorized
  end

  test "email check updates last_seen_at" do
    get api_v1_email_check_path, params: { email: "tracking@example.com" }, headers: @headers
    assert_response :success

    email = Phish::Email.find_by!(email: "tracking@example.com")
    assert_not_nil email.last_seen_at
    assert_in_delta Time.current, email.last_seen_at, 2.seconds
  end

  test "response includes email metadata fields" do
    get api_v1_email_check_path, params: { email: "metadata@example.com" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)

    # Check that metadata fields are present (even if nil)
    assert json.key?("disposable")
    assert json.key?("free_provider")
    assert json.key?("deliverable")
    assert json.key?("valid_mx")
    assert json.key?("reputation_score")
  end

  test "response includes verdict fields" do
    get api_v1_email_check_path, params: { email: "verdict@example.com" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)

    # New emails have unknown verdict
    assert_equal "unknown", json["verdict"]
    assert_nil json["confidence"]
    assert_nil json["verdict_id"]
  end

  test "handles email with plus addressing" do
    get api_v1_email_check_path, params: { email: "user+tag@example.com" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "user+tag@example.com", json["email"]
    assert_equal "example.com", json["domain"]
  end

  test "handles email with subdomain" do
    get api_v1_email_check_path, params: { email: "user@mail.company.co.uk" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "user@mail.company.co.uk", json["email"]
    assert_equal "mail.company.co.uk", json["domain"]
  end
end
