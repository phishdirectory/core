# frozen_string_literal: true

require "test_helper"

# The check endpoints used to create a record and return whatever verdict
# already existed, without ever scheduling a check. These tests pin the
# scheduling behaviour so that cannot regress silently.
class CheckSchedulingTest < ActionDispatch::IntegrationTest
  include ActiveJob::TestHelper

  setup do
    @user = create_test_user
    @api_key = @user.user_api_keys.create!(name: "Test Key")
    @headers = api_headers(api_key: @api_key.plaintext_key)
  end

  # ===========================================
  # Domains
  # ===========================================

  test "checking a brand new domain schedules a check" do
    domain = "new-#{SecureRandom.hex(4)}.com"

    assert_enqueued_with(job: PhishDomainCheckJob) do
      get api_v1_domain_check_path, params: { domain: domain }, headers: @headers
    end

    assert_response :success
  end

  test "checking a domain with a fresh verdict does not schedule a check" do
    domain = Phish::Domain.create!(
      domain: "fresh-#{SecureRandom.hex(4)}.com",
      last_checked_at: 1.minute.ago
    )

    assert_no_enqueued_jobs(only: PhishDomainCheckJob) do
      get api_v1_domain_check_path, params: { domain: domain.domain }, headers: @headers
    end
  end

  test "checking a domain with a stale verdict schedules a check" do
    domain = Phish::Domain.create!(
      domain: "stale-#{SecureRandom.hex(4)}.com",
      last_checked_at: 5.hours.ago
    )

    assert_enqueued_with(job: PhishDomainCheckJob, args: [ domain.id ]) do
      get api_v1_domain_check_path, params: { domain: domain.domain }, headers: @headers
    end
  end

  test "bulk domain check schedules a check for each unchecked domain" do
    domains = 3.times.map { "bulk-#{SecureRandom.hex(4)}.com" }

    assert_enqueued_jobs 3, only: PhishDomainCheckJob do
      post api_v1_domain_bulk_path,
           params: { domains: domains }.to_json,
           headers: @headers
    end

    assert_response :success
  end

  # ===========================================
  # Repeat lookups
  #
  # create_or_find_by! attempts the INSERT and rescues RecordNotUnique from the
  # database, but the uniqueness validation raises RecordInvalid first, so the
  # rescue never fires. Every check of a domain already in the table returned
  # 422 "Domain has already been taken".
  # ===========================================

  test "checking the same domain twice succeeds both times" do
    domain = "repeat-#{SecureRandom.hex(4)}.com"

    get api_v1_domain_check_path, params: { domain: domain }, headers: @headers
    assert_response :success

    get api_v1_domain_check_path, params: { domain: domain }, headers: @headers
    assert_response :success
    assert_equal domain, JSON.parse(response.body)["domain"]
  end

  test "checking the same url twice succeeds both times" do
    url = "https://repeat-#{SecureRandom.hex(4)}.com/login"

    get api_v1_url_check_path, params: { url: url }, headers: @headers
    assert_response :success

    get api_v1_url_check_path, params: { url: url }, headers: @headers
    assert_response :success
  end

  test "checking the same email twice succeeds both times" do
    email = "repeat-#{SecureRandom.hex(4)}@example.com"

    get api_v1_email_check_path, params: { email: email }, headers: @headers
    assert_response :success

    get api_v1_email_check_path, params: { email: email }, headers: @headers
    assert_response :success
  end

  test "checking the same phone number twice succeeds both times" do
    phone = "+1415555#{rand(1000..9999)}"

    get api_v1_phone_check_path, params: { phone: phone }, headers: @headers
    assert_response :success

    get api_v1_phone_check_path, params: { phone: phone }, headers: @headers
    assert_response :success
  end

  test "an invalid record still reports the validation failure rather than a 404" do
    get api_v1_domain_check_path, params: { domain: "not a domain" }, headers: @headers

    assert_response :bad_request
  end

  # ===========================================
  # URLs
  # ===========================================

  test "checking a brand new url schedules a check" do
    url = "https://new-#{SecureRandom.hex(4)}.com/login"

    assert_enqueued_with(job: PhishUrlCheckJob) do
      get api_v1_url_check_path, params: { url: url }, headers: @headers
    end

    assert_response :success
  end

  test "checking a url with a fresh verdict does not schedule a check" do
    url = Phish::Url.create!(
      url: "https://fresh-#{SecureRandom.hex(4)}.com/x",
      last_checked_at: 1.minute.ago
    )

    assert_no_enqueued_jobs(only: PhishUrlCheckJob) do
      get api_v1_url_check_path, params: { url: url.url }, headers: @headers
    end
  end

  test "checking a url records that it was seen" do
    url = "https://seen-#{SecureRandom.hex(4)}.com/x"

    get api_v1_url_check_path, params: { url: url }, headers: @headers

    assert_response :success
    assert Phish::Url.find_by(url: url).last_seen_at.present?
  end

  # ===========================================
  # De-duplication
  #
  # A popular domain is queried constantly. Without a guard every one of those
  # requests would enqueue its own identical check.
  # ===========================================

  test "repeated checks of the same domain enqueue only one job" do
    domain = "hot-#{SecureRandom.hex(4)}.com"

    with_real_cache do
      assert_enqueued_jobs 1, only: PhishDomainCheckJob do
        3.times do
          get api_v1_domain_check_path, params: { domain: domain }, headers: @headers
        end
      end
    end
  end

  private

  # The test environment uses a null store, which cannot hold the
  # de-duplication marker. The guard is designed to fail open, so it only has
  # observable behaviour against a real cache.
  def with_real_cache
    original = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new
    yield
  ensure
    Rails.cache = original
  end
end
