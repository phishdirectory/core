# frozen_string_literal: true

# Webhooks had no subscription list, so WebhookService broadcast every event
# to every endpoint of every service. user.created carries a user's email
# address, which meant every registered endpoint received the email address of
# every user who signed up.
#
# Backfills existing rows with the full event list so no delivery a service
# already relies on stops arriving.
#
# No index: service_webhooks holds one row per registered integration, so a
# sequential scan is the right plan for it.
class AddEventsToServiceWebhooks < ActiveRecord::Migration[8.1]
  def up
    add_column :service_webhooks, :events, :string, array: true, default: [], null: false

    say_with_time "backfilling existing webhooks with the full event list" do
      Service::Webhook.unscoped.update_all(events: Service::Webhook::EVENTS)
    end
  end

  def down
    remove_column :service_webhooks, :events
  end
end
