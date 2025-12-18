# frozen_string_literal: true

class ApplicationController < ActionController::Base
  # Security
  protect_from_forgery with: :exception

  # Ahoy tracking
  before_action :track_ahoy_visit

  # Paper Trail - track who made changes
  before_action :set_paper_trail_whodunnit

  # Helper methods available to views
  helper_method :current_user, :current_session, :user_signed_in?, :impersonating?

  # ===========================================
  # Authentication
  # ===========================================

  def current_user
    return @current_user if defined?(@current_user)

    @current_user = current_session&.user
  end

  def current_session
    return @current_session if defined?(@current_session)

    token = session[:session_token]
    @current_session = token.present? ? User::Session.authenticate(token) : nil
  end

  def user_signed_in?
    current_user.present?
  end

  def authenticate_user!
    unless user_signed_in?
      store_location_for_redirect
      redirect_to login_path, alert: "Please sign in to continue."
    end
  end

  # ===========================================
  # Session Management
  # ===========================================

  def sign_in(user, ip: nil, device_info: nil, impersonator: nil)
    user_session = User::Session.create_for_user(
      user,
      ip: ip || request.remote_ip,
      device_info: device_info || request.user_agent,
      impersonator: impersonator
    )

    session[:session_token] = user_session.session_token
    session[:impersonator_id] = impersonator&.id

    @current_user = user
    @current_session = user_session
  end

  def sign_out
    current_session&.sign_out!
    reset_session
    @current_user = nil
    @current_session = nil
  end

  # ===========================================
  # Impersonation
  # ===========================================

  def impersonating?
    session[:impersonator_id].present?
  end

  def impersonator
    return nil unless impersonating?

    @impersonator ||= User.find_by(id: session[:impersonator_id])
  end

  def stop_impersonating!
    return unless impersonating?

    original_user = impersonator
    sign_out
    sign_in(original_user) if original_user
  end

  # ===========================================
  # Authorization helpers
  # ===========================================

  def require_admin!
    unless current_user&.admin?
      redirect_to root_path, alert: "You don't have permission to access this area."
    end
  end

  def require_superadmin!
    unless current_user&.superadmin?
      redirect_to root_path, alert: "You don't have permission to access this area."
    end
  end

  # ===========================================
  # Paper Trail
  # ===========================================

  def user_for_paper_trail
    current_user&.pd_id || "system"
  end

  # ===========================================
  # Redirect helpers
  # ===========================================

  def store_location_for_redirect
    # Include HEAD requests (Rails routes HEAD to GET actions, but request.get? returns false for HEAD)
    session[:return_to] = request.fullpath if request.get? || request.head?
  end

  def redirect_back_or(default)
    redirect_to(session.delete(:return_to) || default)
  end

  # ===========================================
  # Audits1984 integration
  # ===========================================

  # Required by Audits1984 to identify who is viewing console audits
  def find_current_auditor
    current_user
  end

  # ===========================================
  # Error handling
  # ===========================================

  rescue_from ActiveRecord::RecordNotFound, with: :not_found

  private

  def not_found
    render file: Rails.public_path.join("404.html"), status: :not_found, layout: false
  end
end
