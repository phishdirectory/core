# frozen_string_literal: true

require "test_helper"

class ApiRequestPruneJobTest < ActiveJob::TestCase
  setup do
    @user = create_test_user
    @api_key = @user.user_api_keys.create!(name: "Test Key")
  end

  def build_request(requested_at:)
    ApiRequest.create!(
      authenticatable: @api_key,
      user: @user,
      request_path: "/api/v1/domain/check",
      request_method: "GET",
      response_code: 200,
      requested_at: requested_at
    )
  end

  test "deletes rows older than the retention window and keeps the rest" do
    old = build_request(requested_at: 120.days.ago)
    recent = build_request(requested_at: 2.days.ago)

    ApiRequestPruneJob.perform_now

    assert_not ApiRequest.exists?(old.id)
    assert ApiRequest.exists?(recent.id)
  end

  test "keeps a row that sits exactly inside the window" do
    inside = build_request(requested_at: 89.days.ago)

    ApiRequestPruneJob.perform_now

    assert ApiRequest.exists?(inside.id)
  end

  test "the retention window can be overridden" do
    row = build_request(requested_at: 10.days.ago)

    ApiRequestPruneJob.perform_now(retention: 7.days)

    assert_not ApiRequest.exists?(row.id)
  end

  test "reports what it deleted" do
    build_request(requested_at: 120.days.ago)
    build_request(requested_at: 120.days.ago)

    result = ApiRequestPruneJob.perform_now

    assert_equal 2, result[:api_requests]
  end

  test "prunes service key usage rows too" do
    service = create_test_service
    key = service.service_keys.create!
    usage = Service::KeyUsage.create!(
      key: key,
      request_path: "/api/v1/auth/authenticate",
      request_method: "POST",
      response_code: 200,
      requested_at: 120.days.ago
    )

    ApiRequestPruneJob.perform_now

    assert_not Service::KeyUsage.exists?(usage.id)
  end

  test "does nothing when there is nothing old enough" do
    build_request(requested_at: 1.hour.ago)

    result = ApiRequestPruneJob.perform_now

    assert_equal 0, result[:api_requests]
  end
end
