# frozen_string_literal: true

class Rack::Attack
  ### Configure Cache ###
  #
  # Must be the shared cache, not a per-process one. With an in-process
  # MemoryStore every limit below was enforced per Puma worker, so the real
  # ceiling was the configured limit multiplied by the worker count, and every
  # counter reset on deploy.
  Rack::Attack.cache.store = Rails.cache

  ### Throttle Spammy Clients ###
  # If any single client IP is making tons of requests, then they're
  # having a problem that we can help with. (Alarm bells ring)
  throttle("req/ip", limit: 300, period: 5.minutes) do |req|
    req.ip unless req.path.start_with?("/assets")
  end

  ### Prevent Brute-Force Login Attacks ###
  #
  # These used to point at the wrong paths. POST /auth/login is the magic link
  # request, not the password check, so the "logins" rules throttled magic
  # links; and /auth/send_magic_link matches no route at all, so the
  # "magic_links" rules never fired. The actual password endpoint,
  # POST /auth/password_login, had nothing on it but the blanket per-IP rule.
  PASSWORD_LOGIN_PATH = "/auth/password_login"
  MAGIC_LINK_PATH = "/auth/login"

  def self.normalized_email(req)
    req.params["email"].to_s.downcase.gsub(/\s+/, "")
  end

  throttle("password_logins/ip", limit: 5, period: 20.seconds) do |req|
    req.ip if req.path == PASSWORD_LOGIN_PATH && req.post?
  end

  # Per-account, so rotating source IPs does not buy an attacker unlimited
  # attempts against one person's password.
  throttle("password_logins/email", limit: 5, period: 20.seconds) do |req|
    normalized_email(req).presence if req.path == PASSWORD_LOGIN_PATH && req.post?
  end

  # A slower sustained limit on top of the burst limit above.
  throttle("password_logins/email/hourly", limit: 20, period: 1.hour) do |req|
    normalized_email(req).presence if req.path == PASSWORD_LOGIN_PATH && req.post?
  end

  ### Magic Link Rate Limiting ###
  throttle("magic_links/ip", limit: 3, period: 1.minute) do |req|
    req.ip if req.path == MAGIC_LINK_PATH && req.post?
  end

  throttle("magic_links/email", limit: 3, period: 5.minutes) do |req|
    normalized_email(req).presence if req.path == MAGIC_LINK_PATH && req.post?
  end

  ### Password reset ###
  # Also unthrottled until now, and it sends mail to an address the caller
  # chooses.
  throttle("password_resets/ip", limit: 5, period: 1.hour) do |req|
    req.ip if req.path == "/auth/password/forgot" && req.post?
  end

  throttle("password_resets/email", limit: 3, period: 1.hour) do |req|
    normalized_email(req).presence if req.path == "/auth/password/forgot" && req.post?
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

  # The per-key limits above bucket on the credential itself, so probing with a
  # different invalid key each time lands in a fresh bucket every request. This
  # bounds unauthenticated API traffic by source instead.
  throttle("api/unauthenticated/ip", limit: 30, period: 1.minute) do |req|
    next unless req.path.start_with?("/api/")
    next if req.path.start_with?("/api/v1/health")

    credential = req.get_header("HTTP_X_API_KEY") ||
                 req.get_header("HTTP_AUTHORIZATION")&.gsub(/^Bearer\s+/, "")
    req.ip if credential.blank?
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

    [ 429, headers, [ { error: "Rate limit exceeded. Retry later." }.to_json ] ]
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
