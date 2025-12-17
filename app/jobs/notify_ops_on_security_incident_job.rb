# frozen_string_literal: true

class NotifyOpsOnSecurityIncidentJob < ApplicationJob
  queue_as QUEUE_CRITICAL

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
  end
end
