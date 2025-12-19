# frozen_string_literal: true

class MagicLinkJob < ApplicationJob
  queue_as QUEUE_EMAILS

  def perform(user)
    Rails.logger.info "[MagicLinkJob] Sending magic link to #{user.email}"
    UserMailer.with(user: user).magic_link.deliver_now
  end
end
