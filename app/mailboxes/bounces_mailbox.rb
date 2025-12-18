# frozen_string_literal: true

class BouncesMailbox < ApplicationMailbox
  def process
    # Log unrouted emails
    Rails.logger.info("[BouncesMailbox] Unrouted email from: #{mail.from&.first} to: #{mail.to&.join(', ')}")

    # Mark as bounced (will be deleted after processing)
    bounced!
  end
end
