# frozen_string_literal: true

# Be sure to restart your server when you modify this file.

# Avoid CORS issues when API is called from the frontend app.
# Handle Cross-Origin Resource Sharing (CORS) in order to accept cross-origin Ajax requests.

# Read more: https://github.com/cyu/rack-cors

Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    # Allow requests from phish.directory frontends
    origins(
      "localhost:3000",
      "localhost:3001",
      "127.0.0.1:3000",
      "127.0.0.1:3001",
      /\Ahttps:\/\/.*\.phish\.directory\z/,
      "https://phish.directory"
    )

    resource "/api/*",
      headers: :any,
      methods: %i[get post put patch delete options head],
      expose: %w[X-Request-Id X-Runtime X-RateLimit-Limit X-RateLimit-Remaining X-RateLimit-Reset],
      max_age: 600,
      credentials: true
  end

  # Allow public health checks from anywhere
  allow do
    origins "*"

    resource "/health",
      headers: :any,
      methods: [:get]

    resource "/api/v1/health",
      headers: :any,
      methods: [:get]
  end
end
