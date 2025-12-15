# frozen_string_literal: true

class ApplicationMailer < ActionMailer::Base
  include AhoyEmail if defined?(AhoyEmail)

  default from: email_address_with_name("no-reply@transactional.phish.directory", "Phish Directory")

  layout "mailer"

  # Add UTM params to all links
  before_action :set_utm_params

  protected

  # Add environment prefix to subjects in non-production
  def env_subject(subject)
    if Rails.env.production?
      subject
    else
      "[#{Rails.env.upcase}] #{subject}"
    end
  end

  private

  def set_utm_params
    @utm_params = {
      utm_source: "email",
      utm_medium: "transactional",
      utm_campaign: action_name
    }
  end
end
