# frozen_string_literal: true

require "test_helper"

# The dashboard had no test coverage at all, which is how a hardcoded status
# badge, an unrendered flash key and a completely absent JavaScript runtime all
# survived.
class DashboardRenderingTest < ActionDispatch::IntegrationTest
  setup do
    @user = create_test_user
    sign_in(@user)
  end

  # ===========================================
  # The JavaScript runtime
  # ===========================================

  test "every signed-in layout loads the importmap" do
    get dashboard_root_path
    assert_response :success
    assert_select "script[type=importmap]", 1,
                  "without this Turbo never boots and every data-turbo-confirm is inert"
  end

  test "the docs layout loads the importmap too" do
    get docs_path
    assert_response :success
    assert_select "script[type=importmap]", 1
  end

  # ===========================================
  # Destructive actions must ask first
  # ===========================================

  test "destructive api key actions carry a confirmation" do
    @user.user_api_keys.create!(name: "Key")

    get dashboard_api_keys_path

    assert_response :success
    assert_select "[data-turbo-confirm]", { minimum: 1 },
                  "delete and regenerate must not fire without asking"
  end

  test "terminating a session asks first" do
    # The Terminate button only appears on sessions other than the current one.
    User::Session.create_for_user(@user, ip: "10.0.0.9", device_info: "Another Browser")

    get dashboard_sessions_path

    assert_response :success
    assert_select "[data-turbo-confirm]", minimum: 1
  end

  # ===========================================
  # Status badge
  # ===========================================

  test "an active account shows a success badge" do
    get dashboard_root_path

    assert_response :success
    assert_select "span.bg-success\\/10", text: "Active"
  end

  test "a suspended account does not show a success badge" do
    @user.update_column(:status, "suspended")

    get dashboard_root_path

    assert_response :success
    assert_select "span.bg-success\\/10", { text: "Suspended", count: 0 },
                  "a suspended account showed a green Suspended pill"
    assert_select "span.bg-warning\\/10", text: "Suspended"
  end

  # ===========================================
  # Pages load at all
  # ===========================================

  test "each dashboard page renders" do
    [
      dashboard_root_path,
      dashboard_api_keys_path,
      dashboard_sessions_path,
      dashboard_profile_path,
      dashboard_domain_check_path,
      dashboard_email_check_path,
      dashboard_phone_check_path
    ].each do |path|
      get path
      assert_response :success, "#{path} did not render"
    end
  end
end
