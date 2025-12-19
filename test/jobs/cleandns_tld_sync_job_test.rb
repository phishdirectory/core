# frozen_string_literal: true

require "test_helper"

class CleandnsTldSyncJobTest < ActiveJob::TestCase
  test "job queues in maintenance queue" do
    assert_equal "maintenance", CleandnsTldSyncJob.new.queue_name
  end

  test "job calls service sync" do
    stub_request(:get, "https://api.cleandns.dev/v2/abuse/clients")
      .to_return(
        status: 200,
        body: [ { "tlds" => [ "com" ], "registrars" => [], "resellers" => [] } ].to_json,
        headers: { "Content-Type" => "application/json" }
      )

    assert_nothing_raised do
      CleandnsTldSyncJob.perform_now
    end

    assert Phish::Tld.exists?(name: "com")
  end
end
