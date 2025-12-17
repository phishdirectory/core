# frozen_string_literal: true

# Mission Control Jobs configuration
# Authentication is handled by AdminConstraint in routes.rb
# so we disable the built-in HTTP Basic authentication

MissionControl::Jobs.http_basic_auth_enabled = false
