# frozen_string_literal: true

require "test_helper"

class DomainCheckTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
    @api_key = @user.user_api_keys.create!(name: "Test Key")
    @headers = api_headers(api_key: @api_key.plaintext_key)
  end

  test "can check a domain" do
    get api_v1_domain_check_path, params: { domain: "example.com" }, headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "example.com", json["domain"]
    assert json["verdict"].present?
    assert json["created_at"].present?
  end

  test "domain check normalizes input" do
    get api_v1_domain_check_path,
        params: { domain: "https://WWW.EXAMPLE.COM/path?query=1" },
        headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    # Should normalize to just the domain
    assert_equal "www.example.com", json["domain"]
  end

  test "domain check requires domain parameter" do
    get api_v1_domain_check_path, headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_match(/domain/i, json["error"])
  end

  test "can bulk check domains" do
    post api_v1_domain_bulk_path,
         params: { domains: ["example1.com", "example2.com", "example3.com"] }.to_json,
         headers: @headers

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal 3, json["count"]
    assert_equal 3, json["results"].length
  end

  test "bulk check limits to 100 domains" do
    domains = (1..101).map { |i| "example#{i}.com" }

    post api_v1_domain_bulk_path,
         params: { domains: domains }.to_json,
         headers: @headers

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_match(/100/, json["error"])
  end
end
