# frozen_string_literal: true

module ApplicationHelper
  # Sanitize a URL to only allow http/https protocols
  # Returns nil for potentially dangerous URLs (javascript:, data:, etc.)
  def safe_external_url(url)
    return nil if url.blank?

    uri = URI.parse(url.to_s)
    %w[http https].include?(uri.scheme&.downcase) ? url : nil
  rescue URI::InvalidURIError
    nil
  end

  # Maps a domain concept to a badge tone, so the same state is never coloured
  # one way on one page and another way on the next.
  ACCOUNT_STATUS_TONES = {
    "active" => :success,
    "suspended" => :warning,
    "deactivated" => :danger
  }.freeze

  VERDICT_TONES = {
    "phishing" => :danger,
    "suspicious" => :warning,
    "clean" => :success,
    "protected" => :info,
    "unknown" => :neutral
  }.freeze

  def account_status_tone(status)
    ACCOUNT_STATUS_TONES.fetch(status.to_s, :neutral)
  end

  def verdict_tone(classification)
    VERDICT_TONES.fetch(classification.to_s, :neutral)
  end
end
