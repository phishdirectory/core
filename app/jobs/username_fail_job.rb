# frozen_string_literal: true

class UsernameFailJob < ApplicationJob
  queue_as :default

  def perform(email:, desired_username:)
    # TODO: Notify ops team about username conflict
    Rails.logger.info "[UsernameFailJob] Username conflict for #{email}, desired: #{desired_username}"
  end
end
