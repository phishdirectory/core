# frozen_string_literal: true

class Rack::Attack
  ### Configure Cache ###
  # Use Rails cache for rate limiting
  Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new

  ### Throttle Spammy Clients ###
  # If any single client IP is making tons of requests, then they're
  # having a problem that we can help with. (Alarm bells ring)
  throttle("req/ip", limit: 300, period: 5.minutes) do |req|
    req.ip unless req.path.start_with?("/assets")
  end

  ### Prevent Brute-Force Login Attacks ###
  # Throttle POST requests to /auth/login by IP address
  throttle("logins/ip", limit: 5, period: 20.seconds) do |req|
    req.ip if req.path == "/auth/login" && req.post?
  end

  # Throttle POST requests to /auth/login by email param
  throttle("logins/email", limit: 5, period: 20.seconds) do |req|
    if req.path == "/auth/login" && req.post?
      # Normalize email to prevent bypassing
      req.params["email"].to_s.downcase.gsub(/\s+/, "")
    end
  end

  ### Magic Link Rate Limiting ###
  throttle("magic_links/ip", limit: 3, period: 1.minute) do |req|
    req.ip if req.path == "/auth/send_magic_link" && req.post?
  end

  throttle("magic_links/email", limit: 3, period: 5.minutes) do |req|
    if req.path == "/auth/send_magic_link" && req.post?
      req.params["email"].to_s.downcase.gsub(/\s+/, "")
    end
  end

  ### API Rate Limiting (Sliding Window with Burst Support) ###
  #
  # Multi-tier rate limiting allows bursts while enforcing sustained limits:
  # - Burst:    60 requests per 10 seconds (allows quick bursts)
  # - Short:   200 requests per minute (smooths out usage)
  # - Hourly: 1000 requests per hour (overall cap)
  #
  # All tiers must pass - hitting any limit triggers throttling.
  #
  # NOTE: Upstream services have their own limits (see service classes):
  # - VirusTotal:        4/min, 500/day (most restrictive)
  # - URLScan:           60/min, 100/hour, 1000/day
  # - Google Safe Browsing: 100/min, 10000/day
  # - Walshy:            30/min, 500/hour (conservative)
  #
  # The aggregator gracefully handles rate-limited services and returns
  # results from available services. Responses include rate_limited_services
  # when applicable.

  # Burst limit - allows quick bursts of requests
  throttle("api/burst", limit: 60, period: 10.seconds) do |req|
    if req.path.start_with?("/api/") && !req.path.start_with?("/api/v1/health")
      req.get_header("HTTP_X_API_KEY") || req.get_header("HTTP_AUTHORIZATION")&.gsub(/^Bearer\s+/, "")
    end
  end

  # Short-term limit - smooths out request patterns
  throttle("api/minute", limit: 200, period: 1.minute) do |req|
    if req.path.start_with?("/api/") && !req.path.start_with?("/api/v1/health")
      req.get_header("HTTP_X_API_KEY") || req.get_header("HTTP_AUTHORIZATION")&.gsub(/^Bearer\s+/, "")
    end
  end

  # Hourly limit - overall cap per API key
  throttle("api/hour", limit: 1000, period: 1.hour) do |req|
    if req.path.start_with?("/api/") && !req.path.start_with?("/api/v1/health")
      req.get_header("HTTP_X_API_KEY") || req.get_header("HTTP_AUTHORIZATION")&.gsub(/^Bearer\s+/, "")
    end
  end

  ### Signup Throttling ###
  throttle("signups/ip", limit: 5, period: 1.hour) do |req|
    req.ip if req.path == "/signup" && req.post?
  end

  ### Blocklist Bad Actors ###
  # Block requests from bad IPs (configured elsewhere)
  # blocklist("block bad IPs") do |req|
  #   BadIp.exists?(req.ip)
  # end

  ### Safelist Trusted IPs ###
  # Always allow requests from localhost in development
  safelist("allow from localhost") do |req|
    "127.0.0.1" == req.ip || "::1" == req.ip
  end

  ### Custom Response ###
  self.throttled_responder = lambda do |request|
    match_data = request.env["rack.attack.match_data"]
    now = match_data[:epoch_time]
    headers = {
      "Content-Type" => "application/json",
      "Retry-After" => (match_data[:period] - (now % match_data[:period])).to_s,
      "X-RateLimit-Limit" => match_data[:limit].to_s,
      "X-RateLimit-Remaining" => "0",
      "X-RateLimit-Reset" => (now + (match_data[:period] - now % match_data[:period])).to_s
    }

    [429, headers, [{ error: "Rate limit exceeded. Retry later." }.to_json]]
  end
end

# Log blocked and throttled requests
ActiveSupport::Notifications.subscribe("throttle.rack_attack") do |_name, _start, _finish, _id, payload|
  req = payload[:request]
  Rails.logger.warn "[Rack::Attack] Throttled #{req.ip} - #{req.request_method} #{req.path}"
end

ActiveSupport::Notifications.subscribe("blocklist.rack_attack") do |_name, _start, _finish, _id, payload|
  req = payload[:request]
  Rails.logger.warn "[Rack::Attack] Blocked #{req.ip} - #{req.request_method} #{req.path}"
end
