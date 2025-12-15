# frozen_string_literal: true

class LockboxAudit < ApplicationRecord
  # Associations (polymorphic)
  belongs_to :subject, polymorphic: true, optional: true
  belongs_to :viewer, polymorphic: true, optional: true

  # Scopes
  scope :recent, -> { order(created_at: :desc) }
  scope :for_subject, ->(subject) { where(subject: subject) }
  scope :by_viewer, ->(viewer) { where(viewer: viewer) }
  scope :in_context, ->(context) { where(context: context) }

  # ===========================================
  # Class methods for logging access
  # ===========================================

  class << self
    def log_access(subject:, viewer:, context: nil, data: nil, ip: nil)
      create!(
        subject: subject,
        viewer: viewer,
        context: context,
        data: data,
        ip: ip
      )
    end
  end
end
