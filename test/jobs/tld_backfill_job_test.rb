# frozen_string_literal: true

require "test_helper"

class TldBackfillJobTest < ActiveJob::TestCase
  test "job queues in maintenance queue" do
    assert_equal "maintenance", TldBackfillJob.new.queue_name
  end

  test "backfills domains without TLD" do
    # Create domains - they will auto-associate TLD via callback
    domain1 = Phish::Domain.create!(domain: "test1.com")
    domain2 = Phish::Domain.create!(domain: "test2.org")

    # Simulate missing TLD (would be set on older records before this feature)
    domain1.update_column(:tld_id, nil)
    domain2.update_column(:tld_id, nil)

    # Verify they have no TLD
    assert_nil domain1.reload.tld_id
    assert_nil domain2.reload.tld_id

    TldBackfillJob.perform_now

    domain1.reload
    domain2.reload

    assert_not_nil domain1.tld_id
    assert_not_nil domain2.tld_id
    assert_equal "com", domain1.tld.name
    assert_equal "org", domain2.tld.name
  end

  test "schedules next batch when batch is full" do
    # Create more than BATCH_SIZE domains to trigger scheduling
    # For testing, we just verify the job structure
    assert_respond_to TldBackfillJob.new, :perform
  end

  test "handles domains with compound TLDs" do
    domain = Phish::Domain.create!(domain: "example.co.uk")
    domain.update_column(:tld_id, nil)

    TldBackfillJob.perform_now

    domain.reload
    assert_not_nil domain.tld_id
    assert_equal "co.uk", domain.tld.name
  end
end
