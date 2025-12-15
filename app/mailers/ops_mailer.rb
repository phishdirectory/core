# frozen_string_literal: true

class OpsMailer < ApplicationMailer
  default from: email_address_with_name("ops@transactional.phish.directory", "phish.directory Ops"),
          to: -> { ops_email }

  def new_user_notification
    @user = params[:user]

    mail(subject: env_subject("[NEW USER] #{@user.email} signed up"))
  end

  def security_incident
    @incident_type = params[:incident_type]
    @details = params[:details]
    @user = params[:user]
    @timestamp = params[:timestamp] || Time.current

    mail(subject: env_subject("[SECURITY] #{@incident_type}"))
  end

  def rate_limit_exceeded
    @ip_address = params[:ip_address]
    @endpoint = params[:endpoint]
    @count = params[:count]
    @timestamp = Time.current

    mail(subject: env_subject("[RATE LIMIT] #{@ip_address} exceeded limits"))
  end

  def service_key_created
    @service = params[:service]
    @key = params[:key]
    @created_by = params[:created_by]

    mail(subject: env_subject("[SERVICE KEY] New key created for #{@service.name}"))
  end

  def webhook_delivery_failure
    @webhook = params[:webhook]
    @attempts = params[:attempts]
    @last_error = params[:last_error]

    mail(subject: env_subject("[WEBHOOK] Delivery failed for #{@webhook.url}"))
  end

  def username_conflict
    @email = params[:email]
    @desired_username = params[:desired_username]
    @timestamp = Time.current

    mail(subject: env_subject("[USERNAME] Conflict for #{@email}"))
  end

  private

  def ops_email
    "ops@phish.directory"
  end
end
