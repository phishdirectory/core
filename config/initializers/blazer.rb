# frozen_string_literal: true

# Fix Blazer URL routing for UUID primary keys
# Blazer's default to_param uses "#{id}-#{name.parameterize}" and extracts
# the ID with split("-").first, which breaks UUIDs since they contain dashes.

Rails.application.config.to_prepare do
  Blazer::Query.class_eval do
    def to_param
      id.to_s
    end
  end

  Blazer::Dashboard.class_eval do
    def to_param
      id.to_s
    end
  end
end
