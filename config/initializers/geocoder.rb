# frozen_string_literal: true

# Geocoder configuration for IP geolocation
# Documentation: https://github.com/alexreisner/geocoder

Geocoder.configure(
  # Geocoding service (default is :nominatim for free tier)
  # For production, consider using a paid service like :ipinfo_io or :maxmind
  ip_lookup: :ipinfo_io,

  # API key (required for some services)
  api_key: Rails.application.credentials.dig(:ipinfo, :api_key) || ENV["IPINFO_API_KEY"],

  # Timeout for geocoding requests
  timeout: 3,

  # Geocoding options
  units: :km,
  language: :en,

  # Cache results (recommended for IP lookups)
  cache: Rails.cache,
  cache_options: {
    expiration: 1.day,
    prefix: "geocoder:"
  },

  # Use HTTPS
  use_https: true,

  # Calculation options
  distances: :spherical
)

# Skip geocoding in test environment
if Rails.env.test?
  Geocoder.configure(
    lookup: :test,
    ip_lookup: :test
  )

  # Default test stubs
  Geocoder::Lookup::Test.set_default_stub(
    [
      {
        "coordinates" => [40.7128, -74.0060],
        "address" => "New York, NY, USA",
        "city" => "New York",
        "state" => "New York",
        "country" => "United States"
      }
    ]
  )
end
