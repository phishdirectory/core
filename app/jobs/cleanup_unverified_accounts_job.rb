# frozen_string_literal: true

class CleanupUnverifiedAccountsJob < ApplicationJob
  queue_as QUEUE_MAINTENANCE

  # Clean up accounts that haven't verified email in 7 days
  EXPIRATION_DAYS = 7

  def perform
    cutoff = EXPIRATION_DAYS.days.ago

    users = User.where(email_verified_at: nil)
                .where("created_at < ?", cutoff)
                .where.not(status: :deactivated)

    count = 0
    users.find_each do |user|
      Rails.logger.info("[CleanupUnverifiedAccounts] Deactivating unverified user: #{user.id}")
      user.update!(status: :deactivated)
      count += 1
    end

    Rails.logger.info("[CleanupUnverifiedAccounts] Deactivated #{count} unverified accounts")
    count
  end
end
