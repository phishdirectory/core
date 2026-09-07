# frozen_string_literal: true

module Admin
  # Read-only view of the synced IOK rule corpus.
  #
  # The rows are written by IokSyncJob and read by Phish::IokService, so the
  # only writes offered here are enabling or disabling a single indicator,
  # which is the lever to pull when one rule starts producing false positives.
  class IokIndicatorsController < BaseController
    before_action :set_indicator, only: [ :show, :enable, :disable ]

    def index
      @indicators = Iok::Indicator.kept.order(:title).page(params[:page])
      @indicators = @indicators.tagged(params[:tag]) if params[:tag].present?
      @indicators = search(@indicators, params[:q]) if params[:q].present?

      @tag = params[:tag]
      @query = params[:q]
      @enabled_count = Iok::Indicator.kept.enabled.count
      @disabled_count = Iok::Indicator.kept.where(enabled: false).count
      @last_synced_at = Iok::Indicator.kept.maximum(:synced_at)
    end

    def show
    end

    def enable
      @indicator.update!(enabled: true)
      redirect_to admin_iok_indicator_path(@indicator), notice: "Indicator enabled."
    end

    def disable
      @indicator.update!(enabled: false)
      redirect_to admin_iok_indicator_path(@indicator), notice: "Indicator disabled."
    end

    # The recurring schedule runs daily; this is for pulling a new rule in
    # straight away after it lands upstream.
    def sync
      IokSyncJob.perform_later
      redirect_to admin_iok_indicators_path, notice: "Sync queued."
    end

    private

    def set_indicator
      @indicator = Iok::Indicator.find_by_public_id!(params[:id])
    end

    def search(scope, query)
      scope.where("title ILIKE :q OR slug ILIKE :q", q: "%#{query.strip}%")
    end
  end
end
