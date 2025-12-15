# frozen_string_literal: true

class WelcomeEmailJob < ApplicationJob
  queue_as :default

  def perform(user)
    # TODO: Implement welcome email sending
    Rails.logger.info "[WelcomeEmailJob] Sending welcome email to #{user.email}"
  end
end
