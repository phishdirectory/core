# frozen_string_literal: true

class Ahoy::Store < Ahoy::DatabaseStore
end

# Configure Ahoy
Ahoy.api = true  # Enable API mode
Ahoy.geocode = true  # Enable geocoding

# Set visit duration
Ahoy.visit_duration = 30.minutes

# Mask IPs for privacy (optional - uncomment for GDPR compliance)
# Ahoy.mask_ips = true

# Use cookies for tracking
Ahoy.cookies = :all  # or :none for cookieless

# Track bots (default: false)
Ahoy.track_bots = false

# Set the user method
Ahoy.user_method = :current_user
