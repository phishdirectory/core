# frozen_string_literal: true

class NotifyOpsOnNewUserJob < ApplicationJob
  queue_as :default

  def perform(user)
    Rails.logger.info "[NotifyOpsOnNewUserJob] New user signed up: #{user.pd_id} (#{user.email})"
    OpsMailer.with(user: user).new_user_notification.deliver_now
  end
end
