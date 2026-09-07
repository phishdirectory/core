# frozen_string_literal: true

require "test_helper"

class TrustedSourceApiTest < ActionDispatch::IntegrationTest
  setup do
    @service = create_test_service
    @key = @service.service_keys.create!(trusted_source: true)
    @suffix = SecureRandom.hex(4)
  end

  def post_domains(body, api_key: @key.plaintext_key)
    post api_v1_source_domains_path,
         params: body.to_json,
         headers: api_headers(api_key: api_key)
  end

  # ===========================================
  # Access control
  # ===========================================

  test "a trusted source key may push domains" do
    post_domains({ domains: [ { domain: "push-#{@suffix}.com", classification: "phishing" } ] })

    assert_response :success
    assert_equal "phishing", Phish::Domain.find_by(domain: "push-#{@suffix}.com").verdict.classification
  end

  test "a service key that is not a trusted source is refused" do
    plain_key = @service.service_keys.create!

    post_domains({ domains: [ "refused-#{@suffix}.com" ], classification: "phishing" }, api_key: plain_key.plaintext_key)

    assert_response :forbidden
    assert_not Phish::Domain.exists?(domain: "refused-#{@suffix}.com")
  end

  test "a user api key is refused however senior the user" do
    owner = create_test_user(access_level: :owner)
    user_key = owner.user_api_keys.create!(name: "Owner Key")

    post_domains({ domains: [ "user-#{@suffix}.com" ], classification: "phishing" }, api_key: user_key.plaintext_key)

    assert_response :forbidden
  end

  test "an unauthenticated request is refused" do
    post_domains({ domains: [ "anon-#{@suffix}.com" ], classification: "phishing" }, api_key: nil)

    assert_response :unauthorized
  end

  test "a revoked trusted source key is refused" do
    @key.revoke!

    post_domains({ domains: [ "revoked-#{@suffix}.com" ], classification: "phishing" })

    assert_response :unauthorized
  end

  test "a trusted source key of a suspended service is refused" do
    @service.suspend!

    post_domains({ domains: [ "suspended-#{@suffix}.com" ], classification: "phishing" })

    assert_response :unauthorized
  end

  # ===========================================
  # Request handling
  # ===========================================

  test "reports created and updated counts" do
    domain = "counts-#{@suffix}.com"
    Phish::Domain.create!(domain: domain)

    post_domains({
      classification: "phishing",
      domains: [ domain, "counts-new-#{@suffix}.com" ]
    })

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal 1, json["counts"]["updated"]
    assert_equal 1, json["counts"]["created"]
    assert_equal 2, json["count"]
  end

  test "rejects an empty submission" do
    post_domains({ domains: [] })

    assert_response :bad_request
  end

  test "rejects a submission over the entry cap" do
    oversized = Array.new(TrustedSourceUpsertService::MAX_ENTRIES + 1) { |i| "cap-#{i}-#{@suffix}.com" }

    post_domains({ domains: oversized, classification: "phishing" })

    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_equal oversized.size, json["received"]
  end

  test "reports per entry failures without failing the request" do
    post_domains({
      classification: "phishing",
      domains: [ "not a domain", "mixed-#{@suffix}.com" ]
    })

    assert_response :success
    json = JSON.parse(response.body)
    assert_equal 1, json["counts"]["invalid"]
    assert_equal 1, json["counts"]["created"]
  end

  # ===========================================
  # The other record types
  # ===========================================

  test "a trusted source key may push urls, emails and phone numbers" do
    url = "https://source-#{@suffix}.com/login"
    email = "sender-#{@suffix}@example.com"
    headers = api_headers(api_key: @key.plaintext_key)

    post api_v1_source_urls_path,
         params: { urls: [ url ], classification: "phishing" }.to_json, headers: headers
    assert_response :success

    post api_v1_source_emails_path,
         params: { emails: [ email ], classification: "suspicious" }.to_json, headers: headers
    assert_response :success

    post api_v1_source_phone_numbers_path,
         params: { phone_numbers: [ "+14155551234" ], classification: "phishing" }.to_json, headers: headers
    assert_response :success

    assert_equal "phishing", Phish::Url.find_by(url: url).verdict.classification
    assert_equal "suspicious", Phish::Email.find_by(email: email).verdict.classification
    assert_equal "phishing", Phish::PhoneNumber.find_by(phone_number: "+14155551234").verdict.classification
  end
end
