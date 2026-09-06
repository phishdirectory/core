# frozen_string_literal: true

require "test_helper"

class DomainAvailabilityCheckJobTest < ActiveJob::TestCase
  setup do
    @domain = Phish::Domain.create!(domain: "example.com")
  end

  test "single domain mode updates availability" do
    # Stub the service to return a known result
    mock_result = {
      domain: "example.com",
      dns: { resolvable: true, addresses: [ "93.184.216.34" ], error: nil },
      http: { reachable: true, status: 200, error: nil },
      available: true,
      checked_at: Time.current
    }

    Domain::AvailabilityService.stub(:check, mock_result) do
      DomainAvailabilityCheckJob.perform_now(@domain.id)
    end

    @domain.reload
    assert @domain.dns_resolvable
    assert @domain.http_reachable
    assert @domain.availability_checked_at.present?
  end

  test "batch mode enqueues individual checks for recently seen domains" do
    # Create domains that were recently seen and need checks
    5.times do |i|
      Phish::Domain.create!(
        domain: "test#{i}.example.com",
        last_seen_at: 1.day.ago,
        availability_checked_at: nil
      )
    end

    # Five domains here, plus the one the setup block creates. Each is
    # enqueued exactly once even though it matches both batch queries.
    assert_enqueued_jobs 6, only: DomainAvailabilityCheckJob do
      DomainAvailabilityCheckJob.perform_now
    end
  end

  test "skips domains with recent availability checks" do
    @domain.update!(
      last_seen_at: 1.day.ago,
      availability_checked_at: 30.minutes.ago
    )

    assert_no_enqueued_jobs only: DomainAvailabilityCheckJob do
      DomainAvailabilityCheckJob.perform_now
    end
  end

  test "handles missing domain gracefully" do
    # Should not raise error for non-existent domain
    assert_nothing_raised do
      DomainAvailabilityCheckJob.perform_now("non-existent-uuid")
    end
  end
end
