# frozen_string_literal: true

# StatsD configuration for metrics collection
# Documentation: https://github.com/Shopify/statsd-instrument

# StatsD is configured via environment variables:
# - STATSD_ADDR: The address of the StatsD server (default: localhost:8125)
# - STATSD_ENV: The environment tag
# - STATSD_IMPLEMENTATION: The implementation to use (default: datadog)
# - STATSD_DEFAULT_TAGS: Default tags to add to all metrics

# Set default tags via environment or configure here
ENV["STATSD_ENV"] ||= Rails.env

# Example metric recording:
# StatsD.increment("user.signup", tags: ["region:us"])
# StatsD.measure("api.response_time", tags: ["endpoint:check"]) { heavy_operation }
# StatsD.gauge("queue.size", queue.length, tags: ["queue:default"])
