# frozen_string_literal: true

require "test_helper"

class PhishUrlCheckJobTest < ActiveJob::TestCase
  # Stands in for the aggregator so the job can run without network access.
  class FakeAggregator
    def initialize(result)
      @result = result
    end

    def check_url(_url)
      @result
    end
  end

  setup do
    @url = Phish::Url.create!(url: "https://bad-#{SecureRandom.hex(4)}.example.com/login")
  end

  def with_aggregator_returning(result, &block)
    Phish::AggregatorService.stub(:new, FakeAggregator.new(result), &block)
  end

  # This job previously wrote verdict:, confidence: and details:, none of which
  # are columns on verdicts. It raised UnknownAttributeError on every run and
  # was only hidden because its one call site was commented out.
  test "writes the verdict using the columns that exist on verdicts" do
    result = {
      verdict: "phishing",
      confidence: 0.93,
      details: { service_results: [ { service: "walshy", verdict: "phishing" } ] }
    }

    with_aggregator_returning(result) do
      PhishUrlCheckJob.perform_now(@url.id)
    end

    @url.reload
    assert_not_nil @url.verdict
    assert_equal "phishing", @url.verdict.classification
    assert_in_delta 0.93, @url.verdict.confidence_score, 0.001
    assert_equal 1, @url.verdict.sources.size
    assert @url.last_checked_at.present?
  end

  test "a clean result is recorded without raising" do
    result = { verdict: "clean", confidence: 0.88, details: { service_results: [] } }

    with_aggregator_returning(result) do
      PhishUrlCheckJob.perform_now(@url.id)
    end

    assert_equal "clean", @url.reload.verdict.classification
  end

  test "an unknown result does not erase an established verdict" do
    with_aggregator_returning({ verdict: "phishing", confidence: 0.95, details: {} }) do
      PhishUrlCheckJob.perform_now(@url.id)
    end

    with_aggregator_returning({ verdict: "unknown", confidence: 0.0, details: { all_services_failed: true } }) do
      PhishUrlCheckJob.perform_now(@url.id)
    end

    assert_equal "phishing", @url.reload.verdict.classification
  end

  test "a missing record is discarded rather than retried forever" do
    assert_nothing_raised do
      perform_enqueued_jobs do
        PhishUrlCheckJob.perform_later(SecureRandom.uuid)
      end
    end
  end
end
