# frozen_string_literal: true

class WelcomeEmailJob < ApplicationJob
  queue_as QUEUE_EMAILS

  def perform(user)
    Rails.logger.info "[WelcomeEmailJob] Sending welcome email to #{user.email}"
    UserMailer.with(user: user).welcome.deliver_now
  end
end
