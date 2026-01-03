# frozen_string_literal: true

module Saml
  class Authentication < ApplicationRecord
    self.table_name = "saml_authentications"

    # Associations
    belongs_to :user, optional: true
    belongs_to :service_provider, class_name: "Saml::ServiceProvider"

    # Validations
    validates :status, presence: true, inclusion: { in: %w[success failure] }

    # Scopes
    scope :successful, -> { where(status: "success") }
    scope :failed, -> { where(status: "failure") }
    scope :recent, -> { order(created_at: :desc).limit(100) }
    scope :for_user, ->(user) { where(user: user) }
    scope :for_service_provider, ->(sp) { where(service_provider: sp) }

    # ===========================================
    # Status helpers
    # ===========================================

    def successful?
      status == "success"
    end

    def failed?
      status == "failure"
    end
  end
end
