# frozen_string_literal: true

require "test_helper"

class Api::V1::Domain::WhoisControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
    @api_key = UserApiKey.create!(user: @user, name: "Test Key")
    @auth_headers = api_headers(api_key: @api_key.plaintext_key)
  end

  test "check requires authentication" do
    get api_v1_domain_whois_path, params: { domain: "example.com" }
    assert_response :unauthorized
  end

  test "check requires domain parameter" do
    get api_v1_domain_whois_path, headers: @auth_headers
    assert_response :bad_request
    assert_match(/Missing required parameter/, response.parsed_body["error"])
  end

  test "check validates domain format" do
    get api_v1_domain_whois_path, params: { domain: "invalid..domain" }, headers: @auth_headers
    assert_response :bad_request
    assert_match(/Invalid domain format/, response.parsed_body["error"])
  end

  test "check returns cached result" do
    Phish::DomainRegistration.create!(
      domain: "example.com",
      registrar: "Test Registrar",
      registered_at: 1.year.ago,
      expires_at: 1.year.from_now,
      queried_at: 1.hour.ago
    )

    get api_v1_domain_whois_path, params: { domain: "example.com" }, headers: @auth_headers

    assert_response :success
    assert_equal "example.com", response.parsed_body["domain"]
    assert_equal "Test Registrar", response.parsed_body["registrar"]
  end

  test "check normalizes domain input" do
    Phish::DomainRegistration.create!(
      domain: "example.com",
      registrar: "Test Registrar",
      queried_at: 1.hour.ago
    )

    get api_v1_domain_whois_path, params: { domain: "https://EXAMPLE.COM/path" }, headers: @auth_headers

    assert_response :success
    assert_equal "example.com", response.parsed_body["domain"]
  end

  test "check includes calculated fields" do
    Phish::DomainRegistration.create!(
      domain: "example.com",
      registered_at: 100.days.ago,
      expires_at: 100.days.from_now,
      queried_at: 1.hour.ago
    )

    get api_v1_domain_whois_path, params: { domain: "example.com" }, headers: @auth_headers

    assert_response :success
    # Allow for slight rounding differences
    assert_in_delta 100, response.parsed_body["domain_age_days"], 1
    assert_in_delta 100, response.parsed_body["days_until_expiry"], 1
  end

  test "bulk requires authentication" do
    post api_v1_domain_whois_bulk_path, params: { domains: ["example.com"] }
    assert_response :unauthorized
  end

  test "bulk requires domains parameter" do
    post api_v1_domain_whois_bulk_path, headers: @auth_headers, as: :json
    assert_response :bad_request
  end

  test "bulk limits to 100 domains" do
    domains = (1..101).map { |i| "example#{i}.com" }
    post api_v1_domain_whois_bulk_path,
         params: { domains: domains },
         headers: @auth_headers,
         as: :json

    assert_response :bad_request
    assert_match(/Maximum 100 domains/, response.parsed_body["error"])
  end

  test "bulk validates domain formats" do
    post api_v1_domain_whois_bulk_path,
         params: { domains: ["valid.com", "invalid..domain"] },
         headers: @auth_headers,
         as: :json

    assert_response :bad_request
    assert_match(/Invalid domain format/, response.parsed_body["error"])
  end

  test "bulk returns results for multiple domains" do
    Phish::DomainRegistration.create!(
      domain: "example1.com",
      registrar: "Registrar 1",
      queried_at: 1.hour.ago
    )
    Phish::DomainRegistration.create!(
      domain: "example2.com",
      registrar: "Registrar 2",
      queried_at: 1.hour.ago
    )

    post api_v1_domain_whois_bulk_path,
         params: { domains: ["example1.com", "example2.com"] },
         headers: @auth_headers,
         as: :json

    assert_response :success
    assert_equal 2, response.parsed_body["count"]
    assert_equal 2, response.parsed_body["results"].size
  end
end
