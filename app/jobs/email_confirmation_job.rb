# frozen_string_literal: true

class EmailConfirmationJob < ApplicationJob
  queue_as QUEUE_EMAILS

  def perform(user, token)
    Rails.logger.info "[EmailConfirmationJob] Sending confirmation email to #{user.email}"
    UserMailer.with(user: user, token: token).email_confirmation.deliver_now
  end
end
