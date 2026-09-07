# frozen_string_literal: true

class MagicLinkJob < ApplicationJob
  queue_as QUEUE_EMAILS

  def perform(user, token)
    Rails.logger.info "[MagicLinkJob] Sending magic link to #{user.email}"
    UserMailer.with(user: user, token: token).magic_link.deliver_now
  end
end
