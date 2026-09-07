# frozen_string_literal: true

require "test_helper"

# Blazer runs arbitrary SQL against the primary database. Gated at plain admin,
# it walked around every application-level check: reading credentials straight
# out of the tables, and issuing service keys, which is supposed to require
# superadmin.
class AdminAccessControlTest < ActionDispatch::IntegrationTest
  PRIVILEGED_MOUNTS = %w[
    /admin/blazer
    /admin/flipper
    /admin/jobs
    /admin/pghero
    /admin/console_audits
  ].freeze

  test "a plain admin cannot reach the privileged engines" do
    sign_in(create_test_user(access_level: :admin))

    PRIVILEGED_MOUNTS.each do |path|
      get path
      assert_response :not_found, "#{path} should not resolve for a plain admin"
    end
  end

  test "a regular user cannot reach them either" do
    sign_in(create_test_user)

    PRIVILEGED_MOUNTS.each do |path|
      get path
      assert_response :not_found
    end
  end

  test "a superadmin can reach them" do
    sign_in(create_test_user(access_level: :superadmin))

    # Blazer is the one that matters most; it is also the one that boots
    # cleanly without extra fixtures.
    get "/admin/blazer"

    assert_not_equal 404, response.status,
                     "superadmin must still be able to get in"
  end

  test "the ordinary admin screens are still open to admins" do
    sign_in(create_test_user(access_level: :admin))

    get admin_users_path

    assert_response :success
  end
end
