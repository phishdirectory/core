# frozen_string_literal: true

class BackfillDomainTlds < ActiveRecord::Migration[8.1]
  def up
    # Schedule the backfill job to run after migration
    # This handles the backfill asynchronously to avoid long migration times
    say_with_time "Scheduling TLD backfill job..." do
      TldBackfillJob.perform_later(batch_offset: 0)
    end
  end

  def down
    # No rollback needed - TLDs will remain but can be ignored
  end
end
