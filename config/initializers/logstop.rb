# frozen_string_literal: true

# Logstop: Automatic PII filtering in logs
# Prevents sensitive data from appearing in log files
#
# By default filters: emails, phone numbers, credit cards, SSNs, passwords in URLs
# Custom scrubbers can be added for application-specific secrets

Rails.application.configure do
  # Custom scrubber for PhishDirectory-specific secrets
  custom_scrubber = lambda do |msg|
    # Scrub user API keys (pdat_ prefix)
    msg = msg.gsub(/pdat_[a-zA-Z0-9_\-]{32,}/, "[FILTERED_USER_API_KEY]")

    # Scrub service API keys (64 hex chars)
    msg = msg.gsub(/\b[a-f0-9]{64}\b/, "[FILTERED_API_KEY]")

    # Scrub bearer tokens
    msg = msg.gsub(/Bearer\s+[a-zA-Z0-9\-_\.]+/i, "Bearer [FILTERED]")

    # Scrub magic link tokens
    msg = msg.gsub(/magic_token=[a-zA-Z0-9\-_]+/, "magic_token=[FILTERED]")

    # Scrub session tokens
    msg = msg.gsub(/session_token=[a-zA-Z0-9\-_]+/, "session_token=[FILTERED]")

    msg
  end

  # Guard the Rails logger with PII filtering
  # - ip: true enables IPv4 address filtering
  # - scrubber: adds our custom patterns
  config.after_initialize do
    Logstop.guard(Rails.logger,
      ip: true,
      scrubber: custom_scrubber
    )
  end
end
