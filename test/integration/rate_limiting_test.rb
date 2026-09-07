# frozen_string_literal: true

require "test_helper"

# The throttles pointed at the wrong paths. POST /auth/login is the magic link
# request, not the password check, and /auth/send_magic_link matched no route
# at all, so the rules named after password logins throttled magic links and
# the rules named after magic links never fired. The real password endpoint had
# nothing on it but the blanket per-IP rule.
class RateLimitingTest < ActionDispatch::IntegrationTest
  # Requests from loopback are safelisted, and integration tests come from
  # 127.0.0.1, so every request has to carry a routable source address for any
  # of this to be exercised at all.
  CLIENT_IP = "203.0.113.10"

  setup do
    # The suite runs on a null store, which cannot count. Rack::Attack holds
    # its own handle on the store, so both have to be swapped.
    @original_rails_cache = Rails.cache
    @original_attack_store = Rack::Attack.cache.store

    store = ActiveSupport::Cache::MemoryStore.new
    Rails.cache = store
    Rack::Attack.cache.store = store

    @user = create_test_user
  end

  teardown do
    Rails.cache = @original_rails_cache
    Rack::Attack.cache.store = @original_attack_store
  end

  def from(ip = CLIENT_IP)
    { "REMOTE_ADDR" => ip }
  end

  def attempt_password_login(email: @user.email, ip: CLIENT_IP)
    post password_login_path,
         params: { email: email, password: "wrong-password" },
         headers: from(ip)
  end

  # ===========================================
  # Password login
  # ===========================================

  test "repeated password attempts from one source are throttled" do
    5.times { attempt_password_login }

    attempt_password_login

    assert_response :too_many_requests
  end

  test "the throttle response tells the client when to retry" do
    6.times { attempt_password_login }

    assert_response :too_many_requests
    assert response.headers["Retry-After"].present?
    assert_equal "0", response.headers["X-RateLimit-Remaining"]
  end

  # This is the rule that matters. Bucketing only by IP means an attacker with
  # a pool of addresses gets unlimited attempts against one account.
  test "attempts against one account are throttled even from many addresses" do
    6.times { |i| attempt_password_login(ip: "203.0.113.#{100 + i}") }

    attempt_password_login(ip: "203.0.113.200")

    assert_response :too_many_requests
  end

  test "a single attempt reaches the application rather than the throttle" do
    attempt_password_login

    assert_not_equal 429, response.status,
                     "the first attempt must be handled by the controller, not rejected"
  end

  # ===========================================
  # Magic links
  # ===========================================

  test "magic link requests are throttled" do
    3.times { post login_path, params: { email: @user.email }, headers: from }

    post login_path, params: { email: @user.email }, headers: from

    assert_response :too_many_requests
  end

  test "a first magic link request is allowed through" do
    post login_path, params: { email: @user.email }, headers: from

    assert_response :redirect
  end

  # ===========================================
  # Password reset
  # ===========================================

  test "password reset requests are throttled" do
    3.times { post forgot_password_path, params: { email: @user.email }, headers: from }

    post forgot_password_path, params: { email: @user.email }, headers: from

    assert_response :too_many_requests
  end

  # ===========================================
  # Unauthenticated API probing
  # ===========================================

  test "unauthenticated api requests are bounded by source" do
    30.times do
      get api_v1_domain_check_path, params: { domain: "x.com" }, headers: from.merge("HTTP_USER_AGENT" => "probe/1.0")
    end

    get api_v1_domain_check_path, params: { domain: "x.com" }, headers: from.merge("HTTP_USER_AGENT" => "probe/1.0")

    assert_response :too_many_requests,
                    "per-key buckets do not bound an attacker who sends a new bogus key each time"
  end

  # ===========================================
  # The store
  # ===========================================

  test "the throttle store is the shared cache, not a per-process one" do
    assert_not_instance_of ActiveSupport::Cache::MemoryStore, @original_attack_store,
                           "an in-process store multiplies every limit by the worker count"
  end
end
