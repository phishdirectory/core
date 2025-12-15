# frozen_string_literal: true

class NotifyOpsOnNewUserJob < ApplicationJob
  queue_as :default

  def perform(user)
    # TODO: Implement ops notification (Slack, email, etc.)
    Rails.logger.info "[NotifyOpsOnNewUserJob] New user signed up: #{user.pd_id} (#{user.email})"
  end
end
