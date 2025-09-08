# frozen_string_literal: true

module ApiAuthentication
  extend ActiveSupport::Concern

  included do
    before_action :authenticate_api_key, unless: :skip_api_authentication?
  end

  private

  def authenticate_api_key
    return render_api_unauthorized unless api_key_present?

    @current_api_key = UserApiKey.find_by_key(api_key_from_header)
    return render_api_unauthorized unless @current_api_key&.api_valid?

    # Update last used timestamp
    @current_api_key.touch_last_used!
    
    # Set current user from the API key
    @current_user = @current_api_key.user
  end

  def api_key_present?
    api_key_from_header.present?
  end

  def api_key_from_header
    request.headers['X-API-Key'] || request.headers['HTTP_X_API_KEY']
  end

  def current_api_key
    @current_api_key
  end

  def current_user
    @current_user
  end

  def skip_api_authentication?
    false
  end

  def render_api_unauthorized
    render json: {
      success: false,
      error: {
        message: "Unauthorized - Valid API key required",
        details: ["Include a valid API key in the X-API-Key header"]
      }
    }, status: :unauthorized
  end
end