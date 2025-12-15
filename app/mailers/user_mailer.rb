# frozen_string_literal: true

class UserMailer < ApplicationMailer
  default from: email_address_with_name("no-reply@transactional.phish.directory", "phish.directory"),
          reply_to: email_address_with_name("support@phish.directory", "phish.directory Support")

  def welcome
    @user = params[:user]
    mail(
      to: email_address_with_name(@user.email, @user.full_name),
      from: email_address_with_name("welcome@transactional.phish.directory", "phish.directory"),
      subject: env_subject("Welcome to phish.directory!")
    )
  end

  def magic_link
    @user = params[:user]
    @magic_link_url = magic_link_login_url(token: @user.magic_link_token)
    @expires_at = @user.magic_link_expires_at

    mail(
      to: email_address_with_name(@user.email, @user.full_name),
      from: email_address_with_name("login@transactional.phish.directory", "phish.directory"),
      subject: env_subject("Your login link for phish.directory")
    )
  end

  def login_notification
    @user = params[:user]
    @ip_address = params[:ip_address]
    @timestamp = params[:timestamp]
    @user_agent = params[:user_agent]
    @location = params[:location]

    mail(
      to: email_address_with_name(@user.email, @user.full_name),
      from: email_address_with_name("logins@transactional.phish.directory", "phish.directory"),
      subject: env_subject("New Sign-in Detected - phish.directory")
    )
  end

  def email_confirmation
    @user = params[:user]
    @confirmation_url = confirm_email_url(token: @user.email_confirmation_token)

    mail(
      to: email_address_with_name(@user.email, @user.full_name),
      from: email_address_with_name("confirm@transactional.phish.directory", "phish.directory"),
      subject: env_subject("Please confirm your email address")
    )
  end

  def api_key_created
    @user = params[:user]
    @api_key_name = params[:api_key_name]

    mail(
      to: email_address_with_name(@user.email, @user.full_name),
      subject: env_subject("New API Key Created")
    )
  end
end
