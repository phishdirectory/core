# frozen_string_literal: true

require "test_helper"

class IokSyncJobTest < ActiveSupport::TestCase
  test "runs the sync service" do
    called = false
    service = Object.new
    service.define_singleton_method(:sync) do
      called = true
      { success: true, created: 1, updated: 0, unchanged: 0, invalid: 0, removed: 0 }
    end

    Iok::SyncService.stub(:new, service) { IokSyncJob.perform_now }

    assert called
  end

  test "a failed sync is logged rather than raised" do
    service = Object.new
    service.define_singleton_method(:sync) { { success: false, error: "archive download was empty" } }

    Iok::SyncService.stub(:new, service) do
      assert_nothing_raised { IokSyncJob.perform_now }
    end
  end

  test "runs on the maintenance queue" do
    assert_equal "maintenance", IokSyncJob.new.queue_name
  end

  test "is on the recurring schedule" do
    schedule = YAML.load_file(Rails.root.join("config/recurring.yml"))

    assert_equal "IokSyncJob", schedule.dig("iok_sync", "class")
  end
end
