# frozen_string_literal: true

require "test_helper"

# Every admin index opened with three or four unfiltered COUNT(*) calls over
# tables the product exists to grow, and several printed a per-row count that
# ignored the controller's eager loading.
class AdminIndexPerformanceTest < ActionDispatch::IntegrationTest
  setup do
    @original_cache = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new
    sign_in(create_test_user(access_level: :admin))
  end

  teardown do
    Rails.cache = @original_cache
  end

  def count_queries
    queries = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") do |*, payload|
      next if payload[:name].in?([ "SCHEMA", "TRANSACTION" ])

      queries << payload[:sql]
    end
    yield
    queries
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end

  test "the domain index does not scale its query count with the number of rows" do
    3.times { |i| Phish::Domain.create!(domain: "few-#{i}-#{SecureRandom.hex(3)}.com") }
    baseline = count_queries { get admin_domains_path }.size

    Rails.cache.clear
    20.times { |i| Phish::Domain.create!(domain: "many-#{i}-#{SecureRandom.hex(3)}.com") }
    scaled = count_queries { get admin_domains_path }.size

    assert_response :success
    assert_operator scaled, :<=, baseline + 2,
                    "query count grew with row count, which means an N+1"
  end

  test "the verdict index does not run a count per row" do
    5.times do
      verdict = Verdict.create!(classification: "phishing", confidence_score: 0.9)
      Phish::Domain.create!(domain: "v-#{SecureRandom.hex(4)}.com", verdict: verdict)
    end

    queries = count_queries { get admin_verdicts_path }

    assert_response :success
    counts = queries.count { |sql| sql.include?("COUNT(") && sql.include?("phish_domains") }
    assert_operator counts, :<=, 2,
                    "phish_domains.count inside the row loop ignores the includes"
  end

  test "the service index preloads webhooks" do
    3.times do
      service = create_test_service
      service.service_webhooks.create!(url: "https://hooks.example.com/#{SecureRandom.hex(4)}")
    end

    queries = count_queries { get admin_services_path }

    assert_response :success
    webhook_queries = queries.count { |sql| sql.include?("service_webhooks") }
    assert_operator webhook_queries, :<=, 2,
                    "one webhook query per service row"
  end

  test "repeat views reuse the cached counters" do
    Phish::Domain.create!(domain: "cached-#{SecureRandom.hex(4)}.com")

    get admin_domains_path
    second = count_queries { get admin_domains_path }

    assert_response :success
    aggregate = second.count { |sql| sql.include?("COUNT(") }
    assert_operator aggregate, :<=, 2,
                    "the header counters should come from the cache on a repeat view"
  end
end
