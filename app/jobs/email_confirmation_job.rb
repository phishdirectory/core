# frozen_string_literal: true

class EmailConfirmationJob < ApplicationJob
  queue_as :mailers

  def perform(user_id)
    user = User.find_by(id: user_id)
    return unless user
    return if user.email_confirmed?

    UserMailer.with(user: user).email_confirmation.deliver_now
  end
end
