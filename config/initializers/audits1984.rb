# frozen_string_literal: true

# Audits1984 configuration
# Authentication is handled by AdminConstraint in routes.rb

# The base controller that Audits1984 controllers inherit from
# Must implement #find_current_auditor (defined in ApplicationController)
Audits1984.base_controller_class = "ApplicationController"
