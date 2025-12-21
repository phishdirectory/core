# frozen_string_literal: true

# Fix Blazer URL routing for UUID primary keys
# Blazer's default to_param uses "#{id}-#{name.parameterize}" and extracts
# the ID with split("-").first, which breaks UUIDs since they contain dashes.

module BlazerUuidSupport
  UUID_REGEX = /\A([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i

  def self.extract_id(param)
    if param =~ UUID_REGEX
      ::Regexp.last_match(1)
    else
      param.to_s.split("-").first
    end
  end
end

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

  Blazer::BaseController.class_eval do
    private

    def extract_id(param)
      BlazerUuidSupport.extract_id(param)
    end
  end

  Blazer::QueriesController.class_eval do
    private

    def set_query
      @query = Blazer::Query.find(BlazerUuidSupport.extract_id(params[:id]))
    end
  end

  Blazer::DashboardsController.class_eval do
    private

    def set_dashboard
      @dashboard = Blazer::Dashboard.find(BlazerUuidSupport.extract_id(params[:id]))
    end
  end
end
