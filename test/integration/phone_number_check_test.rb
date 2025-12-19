# frozen_string_literal: true

require "test_helper"

class PhoneNumberCheckTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
    @api_key = @user.user_api_keys.create!(name: "Test Key")
    @headers = api_headers(api_key: @api_key.plaintext_key)
  end

  test "can check a phone number" do
    get api_v1_phone_check_path, params: { phone: "+14155551234" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "+14155551234", json["phone_number"]
    assert json["verdict"].present?
    assert json["created_at"].present?
    assert json["id"].start_with?("phn_")
  end

  test "phone number check normalizes input" do
    get api_v1_phone_check_path,
        params: { phone: "+1 (415) 555-1234" },
        headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "+14155551234", json["phone_number"]
  end

  test "phone number check extracts country code" do
    get api_v1_phone_check_path,
        params: { phone: "+14155551234" },
        headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "US", json["country_code"]
  end

  test "phone number check requires phone parameter" do
    get api_v1_phone_check_path, headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_match(/phone/i, json["error"])
  end

  test "phone number check rejects invalid format" do
    get api_v1_phone_check_path,
        params: { phone: "not-a-phone" },
        headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_match(/E.164/i, json["error"])
  end

  test "can bulk check phone numbers" do
    post api_v1_phone_bulk_path,
         params: { phones: ["+14155551234", "+14155555678", "+14155559999"] }.to_json,
         headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal 3, json["count"]
    assert_equal 3, json["results"].length
  end

  test "bulk check limits to 100 phone numbers" do
    phones = (1..101).map { |i| "+1415555#{i.to_s.rjust(4, '0')}" }

    post api_v1_phone_bulk_path,
         params: { phones: phones }.to_json,
         headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_match(/100/, json["error"])
  end

  test "bulk check returns phone numbers in order" do
    phones = ["+14155551111", "+14155552222", "+14155553333"]

    post api_v1_phone_bulk_path,
         params: { phones: phones }.to_json,
         headers: @headers

    assert_response :success
    json = JSON.parse(response.body)

    assert_equal "+14155551111", json["results"][0]["phone_number"]
    assert_equal "+14155552222", json["results"][1]["phone_number"]
    assert_equal "+14155553333", json["results"][2]["phone_number"]
  end

  test "bulk check deduplicates phone numbers" do
    phones = ["+14155551234", "+14155551234", "+14155551234"]

    post api_v1_phone_bulk_path,
         params: { phones: phones }.to_json,
         headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    # Deduplication means only 1 unique phone number
    assert_equal 1, json["count"]
  end

  test "bulk check reports invalid phone numbers" do
    phones = ["+14155551234", "invalid", "+14155555678"]

    post api_v1_phone_bulk_path,
         params: { phones: phones }.to_json,
         headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert json["invalid_phones"].present?
    assert_includes json["invalid_phones"], "invalid"
  end

  test "phone check requires authentication" do
    get api_v1_phone_check_path, params: { phone: "+14155551234" }

    assert_response :unauthorized
  end

  test "phone number check updates last_seen_at" do
    get api_v1_phone_check_path, params: { phone: "+14155551234" }, headers: @headers
    assert_response :success

    phone = Phish::PhoneNumber.find_by!(phone_number: "+14155551234")
    assert_not_nil phone.last_seen_at
    assert_in_delta Time.current, phone.last_seen_at, 2.seconds
  end

  test "response includes carrier field" do
    get api_v1_phone_check_path, params: { phone: "+14155551111" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert json.key?("carrier"), "Response should include carrier field"
    # Carrier is nil for new phone numbers without carrier lookup
    assert_nil json["carrier"]
  end

  test "response includes verdict fields" do
    get api_v1_phone_check_path, params: { phone: "+14155552222" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    # New phone numbers have unknown verdict and nil confidence
    assert_equal "unknown", json["verdict"]
    assert_nil json["confidence"]
    assert_nil json["verdict_id"]
  end
end
