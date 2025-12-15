# frozen_string_literal: true

class NotifyOpsOnSlackErrorJob < ApplicationJob
  queue_as :default

  def perform(email, error_message)
    Rails.logger.error("[SlackInvite] Failed to invite #{email}: #{error_message}")

    OpsMailer.with(
      email: email,
      error: error_message
    ).slack_invite_error.deliver_now

    # Record metric
    if defined?(StatsD)
      StatsD.increment("slack.invite_errors")
    end
  end
end
