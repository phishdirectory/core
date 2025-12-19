# frozen_string_literal: true

# Scrapes phishing-related subreddits for domain/URL reports
# Runs every 6 hours
class RedditSyncJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  def perform
    Rails.logger.info("[RedditSyncJob] Starting Reddit scrape...")

    service = Phish::RedditService.new
    # Use 8 hours to overlap with 6-hour schedule
    result = service.sync_subreddits(hours: 8)

    if result[:success]
      Rails.logger.info(
        "[RedditSyncJob] Scrape complete: #{result[:posts]} posts, #{result[:domains]} domains"
      )
    else
      Rails.logger.warn(
        "[RedditSyncJob] Scrape completed with errors: #{result[:errors]&.join(', ')}"
      )
    end
  end
end
