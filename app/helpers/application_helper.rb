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
end
