# frozen_string_literal: true

module Auth
  class PasswordsController < ApplicationController
    before_action :redirect_if_authenticated, only: [:new, :create, :edit, :update]

    # GET /auth/password/forgot
    def new
      # Renders forgot password form
    end

    # POST /auth/password/forgot
    def create
      email = params[:email]&.strip&.downcase

      if email.blank?
        flash.now[:alert] = "Please enter your email address."
        render :new, status: :unprocessable_entity
        return
      end

      user = User.find_by(email: email)

      if user&.can_authenticate? && user.has_password?
        user.send_password_reset
      end

      # Always show success message to prevent email enumeration
      redirect_to login_path, notice: "If an account exists with that email and has a password set, you'll receive reset instructions."
    end

    # GET /auth/password/reset/:token
    def edit
      @user = User.find_by(password_reset_token: params[:token])

      if @user.nil? || !@user.password_reset_token_valid?
        redirect_to forgot_password_path, alert: "This password reset link is invalid or has expired."
      end
    end

    # PATCH /auth/password/reset/:token
    def update
      @user = User.find_by(password_reset_token: params[:token])

      if @user.nil? || !@user.password_reset_token_valid?
        redirect_to forgot_password_path, alert: "This password reset link is invalid or has expired."
        return
      end

      if @user.reset_password!(params[:password], params[:password_confirmation])
        redirect_to login_path, notice: "Your password has been reset. You can now sign in."
      else
        flash.now[:alert] = @user.errors.full_messages.to_sentence
        render :edit, status: :unprocessable_entity
      end
    end

    private

    def redirect_if_authenticated
      redirect_to dashboard_root_path if user_signed_in?
    end
  end
end
