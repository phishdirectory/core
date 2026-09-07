# frozen_string_literal: true

# Cached counters for the admin index headers.
#
# Every admin index opened with three or four unfiltered COUNT(*) calls, run
# fresh on every page load, over tables the product exists to grow. On
# api_requests, the highest-write table in the app, that was four full counts
# per view.
#
# These numbers are glanceable context, not figures anyone reconciles, so a
# short cache is the right trade.
module AdminStatsHelper
  STATS_TTL = 1.minute

  # One grouped query instead of one COUNT per classification.
  def verdict_counts(model)
    cached_stat("#{model.name}/by_classification") do
      model.joins(:verdict).group("verdicts.classification").count
    end
  end

  def total_count(model)
    cached_stat("#{model.name}/total") { model.count }
  end

  # api_requests only: grouped by response class in a single pass.
  def api_request_status_counts
    cached_stat("ApiRequest/by_status_class") do
      ApiRequest.group("response_code / 100").count.transform_keys(&:to_i)
    end
  end

  private

  def cached_stat(key, &block)
    Rails.cache.fetch("admin:stats:#{key}", expires_in: STATS_TTL, &block)
  end
end
