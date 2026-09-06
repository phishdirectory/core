# frozen_string_literal: true

require "test_helper"

class MagicLinkFlowTest < ActionDispatch::IntegrationTest
  test "user can request magic link" do
    user = create_test_user

    # Request magic link
    post login_path, params: { email: user.email }

    assert_redirected_to login_path
    follow_redirect!
    assert_response :success

    # Verify magic link was generated
    user.reload
    assert_not_nil user.magic_link_token
    assert_not_nil user.magic_link_expires_at
    assert user.magic_link_expires_at > Time.current
  end

  test "user can login with valid magic link" do
    user = create_test_user
    user.send_magic_link

    # Use magic link
    get magic_link_login_path(token: user.magic_link_token)

    assert_redirected_to dashboard_root_path
    follow_redirect!
    assert_response :success

    # Verify token was consumed. The token stays on the record and is marked
    # used, so magic_link_valid? is what rejects a second use.
    user.reload
    assert user.magic_link_used_at.present?
    assert_not user.magic_link_valid?
  end

  test "expired magic link is rejected" do
    user = create_test_user
    user.update!(
      magic_link_token: SecureRandom.urlsafe_base64(32),
      magic_link_expires_at: 1.hour.ago
    )

    get magic_link_login_path(token: user.magic_link_token)

    assert_redirected_to login_path
    follow_redirect!
    assert_match(/expired|invalid/i, flash[:alert])
  end

  test "invalid magic link is rejected" do
    get magic_link_login_path(token: "invalid-token")

    assert_redirected_to login_path
  end

  test "user can logout" do
    user = create_test_user
    user.send_magic_link
    get magic_link_login_path(token: user.magic_link_token)

    delete logout_path

    assert_redirected_to root_path
  end
end
