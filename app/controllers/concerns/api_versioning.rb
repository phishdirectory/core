# frozen_string_literal: true

module ApiVersioning
  extend ActiveSupport::Concern

  included do
    before_action :set_api_version_headers
  end

  private

  def set_api_version_headers
    response.headers['X-API-Version'] = api_version
    response.headers['X-API-Deprecated'] = deprecated_version? ? 'true' : 'false'
    
    if deprecated_version?
      response.headers['X-API-Sunset'] = sunset_date if sunset_date
      response.headers['Link'] = next_version_link if next_version_link
    end
  end

  def api_version
    'v1'
  end

  def deprecated_version?
    false # v1 is not deprecated yet
  end

  def sunset_date
    # When this version will be removed (ISO 8601 format)
    nil
  end

  def next_version_link
    # Link to next API version documentation
    nil
  end
end