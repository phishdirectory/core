# frozen_string_literal: true

module Auth
  class ConfirmationsController < ApplicationController
    # GET /auth/confirm/:token
    def show
      user = User.find_by(confirmation_token: params[:token])

      if user.nil?
        redirect_to login_path, alert: "Invalid confirmation link."
        return
      end

      unless user.confirmation_token_valid?
        redirect_to login_path, alert: "This confirmation link has expired. Please request a new one."
        return
      end

      user.confirm!

      if user_signed_in? && current_user == user
        redirect_to dashboard_root_path, notice: "Your email has been confirmed."
      else
        redirect_to login_path, notice: "Your email has been confirmed. You can now sign in."
      end
    end

    # POST /auth/confirm/resend
    def create
      if user_signed_in?
        if current_user.confirmed?
          redirect_to dashboard_root_path, notice: "Your email is already confirmed."
        else
          current_user.send_confirmation_email
          redirect_to dashboard_root_path, notice: "A new confirmation email has been sent."
        end
      else
        email = params[:email]&.strip&.downcase
        user = User.find_by(email: email)

        if user && !user.confirmed?
          user.send_confirmation_email
        end

        # Always show success to prevent enumeration
        redirect_to login_path, notice: "If your email needs confirmation, you'll receive instructions shortly."
      end
    end
  end
end
