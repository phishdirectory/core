# frozen_string_literal: true

require "test_helper"

# Auth tokens are stored as digests. Read access to the users table used to be
# account takeover for anyone with a link outstanding.
class UserAuthTokenTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  setup do
    @user = create_test_user
  end

  # ===========================================
  # Nothing usable is left in the database
  # ===========================================

  test "the raw magic link token is never persisted" do
    token = @user.generate_magic_link_token

    assert token.present?
    stored = User.find(@user.id)
    assert_equal User.digest_token(token), stored.magic_link_token_digest
    assert_nil stored.magic_link_token, "the raw token must not be in the database"
    assert_not_equal token, stored.magic_link_token_digest
  end

  test "the raw password reset token is never persisted" do
    token = @user.generate_password_reset_token

    stored = User.find(@user.id)
    assert_equal User.digest_token(token), stored.password_reset_token_digest
    assert_nil stored.password_reset_token
  end

  test "the raw confirmation token is never persisted" do
    token = @user.generate_confirmation_token

    stored = User.find(@user.id)
    assert_equal User.digest_token(token), stored.confirmation_token_digest
    assert_nil stored.confirmation_token
  end

  test "a stolen digest cannot be used as a token" do
    @user.generate_magic_link_token
    digest = @user.reload.magic_link_token_digest

    assert_nil User.find_by_magic_link_token(digest),
               "presenting the stored value must not authenticate anyone"
  end

  # ===========================================
  # Lookup
  # ===========================================

  test "a user is found by their raw magic link token" do
    token = @user.generate_magic_link_token

    assert_equal @user, User.find_by_magic_link_token(token)
  end

  test "a user is found by their raw password reset token" do
    token = @user.generate_password_reset_token

    assert_equal @user, User.find_by_password_reset_token(token)
  end

  test "a user is found by their raw confirmation token" do
    token = @user.generate_confirmation_token

    assert_equal @user, User.find_by_confirmation_token(token)
  end

  test "an unknown or blank token finds nobody" do
    assert_nil User.find_by_magic_link_token("nope")
    assert_nil User.find_by_magic_link_token(nil)
    assert_nil User.find_by_magic_link_token("")
  end

  test "one user's token does not match another user" do
    other = create_test_user
    token = @user.generate_magic_link_token
    other.generate_magic_link_token

    assert_equal @user, User.find_by_magic_link_token(token)
  end

  # ===========================================
  # Validity still behaves
  # ===========================================

  test "a fresh magic link is valid and an expired one is not" do
    @user.generate_magic_link_token
    assert @user.magic_link_valid?

    @user.update!(magic_link_expires_at: 1.minute.ago)
    assert_not @user.magic_link_valid?
  end

  test "a consumed magic link cannot be reused" do
    @user.generate_magic_link_token

    assert @user.consume_magic_link_token!
    assert_not @user.magic_link_valid?
    assert_not @user.consume_magic_link_token!
  end

  test "confirming clears the stored digest" do
    @user.generate_confirmation_token
    assert @user.confirmation_token_valid?

    @user.confirm!

    assert_nil @user.reload.confirmation_token_digest
    assert_not @user.confirmation_token_valid?
  end

  test "resetting a password clears the stored digest" do
    @user.generate_password_reset_token
    assert @user.password_reset_token_valid?

    assert @user.reset_password!("Str0ng-Passw0rd!", "Str0ng-Passw0rd!")

    assert_nil @user.reload.password_reset_token_digest
    assert_not @user.password_reset_token_valid?
  end

  test "an expired password reset token is refused" do
    @user.generate_password_reset_token
    @user.update!(password_reset_expires_at: 1.minute.ago)

    assert_not @user.password_reset_token_valid?
    assert_not @user.reset_password!("Str0ng-Passw0rd!", "Str0ng-Passw0rd!")
  end

  # ===========================================
  # Delivery
  # ===========================================

  test "the raw token is handed to the mailer job, not read back from the record" do
    assert_enqueued_with(job: MagicLinkJob) do
      @user.send_magic_link
    end

    enqueued = enqueued_jobs.last
    raw_token = enqueued[:args].last

    assert raw_token.is_a?(String)
    assert_equal @user, User.find_by_magic_link_token(raw_token)
  end
end
