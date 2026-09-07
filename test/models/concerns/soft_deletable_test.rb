# frozen_string_literal: true

require "test_helper"

# Discarding a record used to burn its natural key forever: the unique indexes
# ignored discarded_at and the uniqueness validator does not respect the
# model's default scope, so the value could never be used again.
class SoftDeletableTest < ActiveSupport::TestCase
  # Natural keys a caller supplies again. These must be reusable after a
  # discard.
  test "a discarded domain does not block re-adding the same domain" do
    name = "reuse-#{SecureRandom.hex(4)}.com"
    Phish::Domain.create!(domain: name).discard!

    fresh = Phish::Domain.new(domain: name)

    assert fresh.valid?, fresh.errors.full_messages.join(", ")
    assert fresh.save
    assert_equal 1, Phish::Domain.where(domain: name).count
  end

  test "a discarded url does not block re-adding the same url" do
    value = "https://reuse-#{SecureRandom.hex(4)}.com/x"
    Phish::Url.create!(url: value).discard!

    assert Phish::Url.new(url: value).save
  end

  test "a discarded service does not block re-using its name" do
    name = "svc-#{SecureRandom.hex(4)}"
    Service.create!(name: name).discard!

    assert Service.new(name: name).save
  end

  test "a discarded webhook does not block re-registering the same url" do
    service = Service.create!(name: "svc-#{SecureRandom.hex(4)}")
    url = "https://hooks.example.com/#{SecureRandom.hex(4)}"
    service.service_webhooks.create!(url: url).discard!

    assert service.service_webhooks.new(url: url).save
  end

  test "a discarded user does not block re-using their email" do
    email = "reuse-#{SecureRandom.hex(4)}@example.com"
    create_test_user(email: email).discard!

    assert create_test_user(email: email).persisted?
  end

  test "the natural key is still unique among live records" do
    name = "dup-#{SecureRandom.hex(4)}.com"
    Phish::Domain.create!(domain: name)

    duplicate = Phish::Domain.new(domain: name)

    assert_not duplicate.valid?
    assert_includes duplicate.errors[:domain], "has already been taken"
  end

  test "the database rejects a duplicate live record even without validation" do
    name = "dup-#{SecureRandom.hex(4)}.com"
    Phish::Domain.create!(domain: name)

    assert_raises(ActiveRecord::RecordNotUnique) do
      Phish::Domain.new(domain: name).save!(validate: false)
    end
  end

  # System-generated identifiers must stay globally unique: reusing one is a
  # collision, not a re-registration.
  test "pd_id stays unique across discarded users" do
    user = create_test_user
    pd_id = user.pd_id
    user.discard!

    collision = User.new(
      email: "other-#{SecureRandom.hex(4)}@example.com",
      first_name: "A", last_name: "B", pd_id: pd_id
    )

    assert_not collision.valid?
    assert_includes collision.errors[:pd_id], "has already been taken"
  end

  test "an api key digest stays unique across discarded keys" do
    user = create_test_user
    key = user.user_api_keys.create!(name: "K")
    digest = key.key_digest
    key.discard!

    collision = user.user_api_keys.new(name: "K2", key_digest: digest)

    assert_raises(ActiveRecord::RecordNotUnique) do
      collision.save!(validate: false)
    end
  end
end
