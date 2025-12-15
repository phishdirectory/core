# frozen_string_literal: true

class NotifyOpsOnSecurityIncidentJob < ApplicationJob
  queue_as :critical

  # Known incident types
  INCIDENT_TYPES = %w[
    brute_force_attempt
    suspicious_login
    api_key_abuse
    rate_limit_violation
    unauthorized_access_attempt
    data_exfiltration_attempt
  ].freeze

  def perform(incident_type, details = {}, user_id = nil)
    user = User.find_by(id: user_id) if user_id

    Rails.logger.warn("[SecurityIncident] #{incident_type}: #{details.inspect}")

    # Send email notification
    OpsMailer.with(
      incident_type: incident_type,
      details: details,
      user: user,
      timestamp: Time.current
    ).security_incident.deliver_now

    # Record metric
    if defined?(StatsD)
      StatsD.increment("security.incidents", tags: { type: incident_type })
    end

    # Could also send to Slack, PagerDuty, etc.
    notify_slack(incident_type, details, user) if critical_incident?(incident_type)
  end

  private

  def critical_incident?(incident_type)
    %w[data_exfiltration_attempt unauthorized_access_attempt].include?(incident_type)
  end

  def notify_slack(incident_type, details, user)
    # Placeholder for Slack notification
    Rails.logger.info("[SecurityIncident] Would notify Slack: #{incident_type}")
  end
end
