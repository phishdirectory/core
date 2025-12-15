# frozen_string_literal: true

class WebhookService
  class << self
    def notify_user_role_changed(pd_id, new_level, old_level)
      broadcast_event("user.role_changed", {
        pd_id: pd_id,
        new_access_level: new_level,
        old_access_level: old_level,
        changed_at: Time.current.iso8601
      })
    end

    def notify_user_created(user)
      broadcast_event("user.created", {
        pd_id: user.pd_id,
        email: user.email,
        created_at: user.created_at.iso8601
      })
    end

    def notify_domain_verdict(domain, verdict)
      broadcast_event("domain.verdict", {
        domain: domain.domain,
        classification: verdict.classification,
        confidence: verdict.confidence_score,
        checked_at: Time.current.iso8601
      })
    end

    private

    def broadcast_event(event, payload)
      Service::Webhook.find_each do |webhook|
        webhook.deliver(event: event, payload: payload)
      rescue StandardError => e
        Rails.logger.error "[WebhookService] Failed to queue webhook delivery: #{e.message}"
      end
    end
  end
end
