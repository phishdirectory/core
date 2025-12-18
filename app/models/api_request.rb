# frozen_string_literal: true

class ApiRequest < ApplicationRecord
  # Polymorphic association to UserApiKey or Service::Key
  belongs_to :authenticatable, polymorphic: true
  belongs_to :user, optional: true

  # Scopes for querying
  scope :recent, -> { order(requested_at: :desc) }
  scope :slow, ->(threshold_ms = 1000) { where("duration_ms > ?", threshold_ms) }
  scope :by_status, ->(code) { where(response_code: code) }
  scope :successful, -> { where(response_code: 200..299) }
  scope :client_errors, -> { where(response_code: 400..499) }
  scope :server_errors, -> { where(response_code: 500..599) }
  scope :for_user_keys, -> { where(authenticatable_type: "UserApiKey") }
  scope :for_service_keys, -> { where(authenticatable_type: "Service::Key") }
  scope :today, -> { where(requested_at: Time.current.beginning_of_day..) }
  scope :this_week, -> { where(requested_at: 1.week.ago..) }
  scope :by_path, ->(path) { where(request_path: path) }
  scope :by_method, ->(method) { where(request_method: method.to_s.upcase) }

  # Validations
  validates :request_path, presence: true
  validates :request_method, presence: true
  validates :requested_at, presence: true

  # Status code helpers
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

  # Type helpers
  def user_api_key?
    authenticatable_type == "UserApiKey"
  end

  def service_key?
    authenticatable_type == "Service::Key"
  end

  def service
    authenticatable.service if service_key?
  end

  # JSON parsing helpers for headers/body
  def parsed_request_headers
    return {} if request_headers.blank?

    JSON.parse(request_headers)
  rescue JSON::ParserError
    {}
  end

  def parsed_response_body
    return {} if response_body.blank?

    JSON.parse(response_body)
  rescue JSON::ParserError
    response_body
  end

  def parsed_request_body
    return {} if request_body.blank?

    JSON.parse(request_body)
  rescue JSON::ParserError
    request_body
  end
end
