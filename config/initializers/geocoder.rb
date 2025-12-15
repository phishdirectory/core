# frozen_string_literal: true

# Geocoder configuration for IP geolocation
# Documentation: https://github.com/alexreisner/geocoder

Geocoder.configure(
  # Geocoding service - using free geoip2 lookup
  ip_lookup: :geoip2,

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
