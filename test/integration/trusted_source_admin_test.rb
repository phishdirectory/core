# frozen_string_literal: true

require "test_helper"

# Marking a service key as a trusted source hands it write access to the
# verdicts table, so the grant is gated like any other privilege grant.
class TrustedSourceAdminTest < ActionDispatch::IntegrationTest
  setup do
    @service = create_test_service
    @key = @service.generate_key!
  end

  test "a superadmin can mark a key as a trusted source" do
    sign_in(create_test_user(access_level: :superadmin))

    post trust_admin_service_key_path(@service, @key)

    assert_redirected_to admin_service_path(@service)
    assert @key.reload.trusted_source?
  end

  test "a plain admin cannot mark a key as a trusted source" do
    sign_in(create_test_user(access_level: :admin))

    post trust_admin_service_key_path(@service, @key)

    assert_not @key.reload.trusted_source?
  end

  test "a plain admin cannot issue a trusted source key" do
    sign_in(create_test_user(access_level: :admin))

    post admin_service_keys_path(@service), params: { trusted_source: "1" }

    assert_equal 1, @service.service_keys.count
    assert_empty @service.service_keys.trusted_sources
  end

  test "a superadmin can issue a trusted source key" do
    sign_in(create_test_user(access_level: :superadmin))

    post admin_service_keys_path(@service), params: { trusted_source: "1" }

    assert_equal 1, @service.service_keys.trusted_sources.count
  end

  test "a plain admin can withdraw the grant" do
    @key.mark_trusted_source!
    sign_in(create_test_user(access_level: :admin))

    post untrust_admin_service_key_path(@service, @key)

    assert_not @key.reload.trusted_source?
  end

  test "the trusted sources documentation page renders" do
    get docs_page_path(page: "trusted-sources")

    assert_response :success
    assert_select "h1", text: "Trusted Sources"
  end

  test "a regular user cannot reach the trust controls" do
    sign_in(create_test_user)

    post trust_admin_service_key_path(@service, @key)

    assert_not @key.reload.trusted_source?
  end
end
