# frozen_string_literal: true

class Service::KeyUsage < ApplicationRecord
  self.table_name = "service_key_usages"

  # Associations
  belongs_to :key, class_name: "Service::Key"
  belongs_to :user, optional: true

  # Delegations
  delegate :service, to: :key

  # Scopes
  scope :recent, -> { order(requested_at: :desc) }
  scope :slow, ->(threshold_ms = 1000) { where("duration_ms > ?", threshold_ms) }
  scope :by_status, ->(code) { where(response_code: code) }
  scope :successful, -> { where(response_code: 200..299) }
  scope :client_errors, -> { where(response_code: 400..499) }
  scope :server_errors, -> { where(response_code: 500..599) }

  # ===========================================
  # Query helpers
  # ===========================================

  def success?
    response_code.present? && response_code.between?(200, 299)
  end

  def client_error?
    response_code.present? && response_code.between?(400, 499)
  end

  def server_error?
    response_code.present? && response_code.between?(500, 599)
  end

  def slow?(threshold_ms = 1000)
    duration_ms.present? && duration_ms > threshold_ms
  end

  # ===========================================
  # Serialization helpers for headers/body
  # ===========================================

  def parsed_request_headers
    return {} if request_headers.blank?

    JSON.parse(request_headers)
  rescue JSON::ParserError
    {}
  end

  def parsed_response_headers
    return {} if response_headers.blank?

    JSON.parse(response_headers)
  rescue JSON::ParserError
    {}
  end

  def parsed_request_body
    return {} if request_body.blank?

    JSON.parse(request_body)
  rescue JSON::ParserError
    request_body
  end

  def parsed_response_body
    return {} if response_body.blank?

    JSON.parse(response_body)
  rescue JSON::ParserError
    response_body
  end
end
