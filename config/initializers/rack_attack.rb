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

  ### API Rate Limiting ###
  # Authenticated API requests (by API key)
  throttle("api/key", limit: 1000, period: 1.hour) do |req|
    if req.path.start_with?("/api/")
      # Extract API key from header
      req.get_header("HTTP_X_API_KEY") || req.get_header("HTTP_AUTHORIZATION")&.gsub(/^Bearer\s+/, "")
    end
  end

  # Unauthenticated API requests (by IP)
  throttle("api/ip", limit: 100, period: 1.hour) do |req|
    if req.path.start_with?("/api/")
      api_key = req.get_header("HTTP_X_API_KEY") || req.get_header("HTTP_AUTHORIZATION")&.gsub(/^Bearer\s+/, "")
      req.ip if api_key.blank?
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
