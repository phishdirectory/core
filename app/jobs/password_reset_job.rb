# frozen_string_literal: true

class PasswordResetJob < ApplicationJob
  queue_as QUEUE_EMAILS

  def perform(user)
    Rails.logger.info "[PasswordResetJob] Sending password reset to #{user.email}"
    UserMailer.with(user: user).password_reset.deliver_now
  end
end
