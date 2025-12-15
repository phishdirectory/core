# frozen_string_literal: true

class SessionCleanupJob < ApplicationJob
  queue_as :maintenance

  def perform
    # Clean up expired sessions
    expired_count = cleanup_expired_sessions

    # Clean up old signed-out sessions (keep for 30 days for audit)
    old_count = cleanup_old_sessions

    Rails.logger.info("[SessionCleanup] Cleaned up #{expired_count} expired, #{old_count} old sessions")

    { expired: expired_count, old: old_count }
  end

  private

  def cleanup_expired_sessions
    User::Session
      .where("expiration_at < ?", Time.current)
      .where(signed_out_at: nil)
      .update_all(signed_out_at: Time.current)
  end

  def cleanup_old_sessions
    # Delete sessions that were signed out more than 30 days ago
    cutoff = 30.days.ago
    User::Session
      .where.not(signed_out_at: nil)
      .where("signed_out_at < ?", cutoff)
      .delete_all
  end
end
