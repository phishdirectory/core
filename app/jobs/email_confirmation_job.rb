# frozen_string_literal: true

class EmailConfirmationJob < ApplicationJob
  queue_as QUEUE_EMAILS

  def perform(user)
    Rails.logger.info "[EmailConfirmationJob] Sending confirmation email to #{user.email}"
    UserMailer.with(user: user).email_confirmation.deliver_now
  end
end
