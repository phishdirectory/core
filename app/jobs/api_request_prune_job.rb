# frozen_string_literal: true

# api_requests and service_key_usages record one row per API call and had no
# retention at all, so both grew without limit on the busiest write path in
# the application.
#
# Deletes in bounded batches rather than one statement, so a backlog cannot
# hold a long lock on the table.
class ApiRequestPruneJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  # Override with API_REQUEST_RETENTION_DAYS to keep more or less history.
  DEFAULT_RETENTION = 90.days
  BATCH_SIZE = 5_000
  MAX_BATCHES_PER_RUN = 40

  def perform(retention: self.class.retention)
    cutoff = retention.ago

    requests = prune(ApiRequest, :requested_at, cutoff)
    usages = prune(Service::KeyUsage, :requested_at, cutoff)

    Rails.logger.info(
      "[ApiRequestPrune] Deleted #{requests} api_requests and #{usages} " \
      "service_key_usages older than #{cutoff.iso8601}"
    )

    { api_requests: requests, service_key_usages: usages }
  end

  def self.retention
    days = ENV["API_REQUEST_RETENTION_DAYS"].presence
    days ? days.to_i.days : DEFAULT_RETENTION
  end

  private

  def prune(model, timestamp_column, cutoff)
    deleted = 0

    MAX_BATCHES_PER_RUN.times do
      batch = model
                .where(timestamp_column => ...cutoff)
                .limit(BATCH_SIZE)
                .pluck(:id)

      break if batch.empty?

      deleted += model.where(id: batch).delete_all
    end

    deleted
  end
end
