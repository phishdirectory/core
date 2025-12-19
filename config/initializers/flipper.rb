# frozen_string_literal: true

require "flipper"
require "flipper/adapters/active_record"

Flipper.configure do |config|
  config.adapter { Flipper::Adapters::ActiveRecord.new }
end

# Register feature flag groups
Flipper.register(:admins) do |actor|
  actor.respond_to?(:admin?) && actor.admin?
end

Flipper.register(:superadmins) do |actor|
  actor.respond_to?(:superadmin?) && actor.superadmin?
end

Flipper.register(:owners) do |actor|
  actor.respond_to?(:owner?) && actor.owner?
end

Flipper.register(:staff) do |actor|
  actor.respond_to?(:staff?) && actor.staff?
end

Flipper.register(:pd_devs) do |actor|
  actor.respond_to?(:pd_dev?) && actor.pd_dev?
end

Flipper.register(:trusted) do |actor|
  actor.respond_to?(:trusted?) && actor.trusted?
end

# Percentage-based groups
Flipper.register(:beta_users) do |actor, context|
  # 10% of users
  actor.respond_to?(:id) && (actor.id.hash % 100) < 10
end

# Initialize default feature flags
Rails.application.config.after_initialize do
  # Skip if Flipper tables don't exist (e.g., during db:migrate or db:rollback)
  next unless ActiveRecord::Base.connection.table_exists?(:flipper_features)

  # Auto-reporting: Enable automated abuse reporting when phishing is detected
  # Start disabled - enable via admin UI when ready
  unless Flipper.exist?(:auto_reporting)
    Flipper.add(:auto_reporting)
    # Flipper.disable(:auto_reporting) # Disabled by default
  end
end
