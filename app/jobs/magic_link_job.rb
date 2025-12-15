# frozen_string_literal: true

class MagicLinkJob < ApplicationJob
  queue_as :default

  def perform(user)
    # TODO: Implement magic link email sending
    Rails.logger.info "[MagicLinkJob] Sending magic link to #{user.email}"
  end
end
