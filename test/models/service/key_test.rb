# frozen_string_literal: true

require "test_helper"

class Service::KeyTest < ActiveSupport::TestCase
  setup do
    @service = create_test_service
  end

  test "a new key is not a trusted source" do
    key = @service.generate_key!

    assert_not key.trusted_source?
    assert_not key.trusted_source_writer?
  end

  test "a key can be generated as a trusted source" do
    key = @service.generate_key!(trusted_source: true)

    assert key.trusted_source?
    assert key.trusted_source_writer?
  end

  test "trust can be granted and withdrawn on an existing key" do
    key = @service.generate_key!

    key.mark_trusted_source!
    assert key.reload.trusted_source?

    key.unmark_trusted_source!
    assert_not key.reload.trusted_source?
  end

  test "a revoked key is not a trusted source writer even while flagged" do
    key = @service.generate_key!(trusted_source: true)
    key.revoke!

    assert key.trusted_source?
    assert_not key.trusted_source_writer?
  end

  test "a key of a suspended service is not a trusted source writer" do
    key = @service.generate_key!(trusted_source: true)
    @service.suspend!

    assert_not key.reload.trusted_source_writer?
  end

  test "the trusted_sources scope only returns flagged keys" do
    trusted = @service.generate_key!(trusted_source: true)
    @service.generate_key!

    assert_equal [ trusted.id ], @service.service_keys.trusted_sources.pluck(:id)
  end

  test "a service reports whether it holds any usable trusted source key" do
    assert_not @service.trusted_source?

    key = @service.generate_key!(trusted_source: true)
    assert @service.reload.trusted_source?

    key.revoke!
    assert_not @service.reload.trusted_source?
  end
end
