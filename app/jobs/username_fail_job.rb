# frozen_string_literal: true

class UsernameFailJob < ApplicationJob
  queue_as QUEUE_DEFAULT

  def perform(email:, desired_username:)
    Rails.logger.info "[UsernameFailJob] Username conflict for #{email}, desired: #{desired_username}"
    OpsMailer.with(email: email, desired_username: desired_username).username_conflict.deliver_now
  end
end
