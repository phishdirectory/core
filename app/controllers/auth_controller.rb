# frozen_string_literal: true

class AuthController < ApplicationController
  before_action :redirect_if_authenticated, only: [:login, :send_magic_link, :magic_link_login]

  # GET /auth/login
  def login
    # Renders login form
  end

  # POST /auth/login
  def send_magic_link
    email = params[:email]&.strip&.downcase

    if email.blank?
      flash.now[:alert] = "Please enter your email address."
      render :login, status: :unprocessable_entity
      return
    end

    user = User.find_by(email: email)

    if user
      if user.can_authenticate?
        user.send_magic_link
        redirect_to login_path, notice: "Check your email for a magic link to sign in."
      else
        flash.now[:alert] = "Your account is not active. Please contact support."
        render :login, status: :unprocessable_entity
      end
    else
      # Don't reveal whether email exists - always show success message
      redirect_to login_path, notice: "If an account exists with that email, you'll receive a magic link."
    end
  end

  # GET /auth/magic_link/:token
  def magic_link_login
    user = User.find_by(magic_link_token: params[:token])

    if user.nil?
      redirect_to login_path, alert: "Invalid or expired magic link."
      return
    end

    unless user.magic_link_valid?
      redirect_to login_path, alert: "This magic link has expired. Please request a new one."
      return
    end

    unless user.can_authenticate?
      redirect_to login_path, alert: "Your account is not active. Please contact support."
      return
    end

    # Consume the token and sign in
    if user.consume_magic_link_token!
      sign_in(user)

      # Verify email on first magic link login
      user.verify_email! unless user.email_verified?

      redirect_back_or(dashboard_root_path)
    else
      redirect_to login_path, alert: "Unable to sign in. Please try again."
    end
  end

  # DELETE /auth/logout
  def logout
    sign_out
    redirect_to root_path, notice: "You have been signed out."
  end

  # GET /auth/me
  def me
    if user_signed_in?
      render json: {
        user: {
          pd_id: current_user.pd_id,
          public_id: current_user.public_id,
          email: current_user.email,
          name: current_user.full_name,
          username: current_user.username,
          access_level: current_user.access_level,
          email_verified: current_user.email_verified?
        },
        session: {
          impersonating: impersonating?,
          expires_at: current_session.expiration_at
        }
      }
    else
      render json: { error: "Not authenticated" }, status: :unauthorized
    end
  end

  private

  def redirect_if_authenticated
    redirect_to dashboard_root_path if user_signed_in?
  end
end
