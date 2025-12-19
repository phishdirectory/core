# frozen_string_literal: true

module Admin
  class VerdictsController < BaseController
    before_action :set_verdict, only: [:show, :edit, :update]

    def index
      @verdicts = Verdict.includes(:phish_domains, :phish_urls)
                         .order(created_at: :desc)

      # Classification filter
      if params[:classification].present? && Verdict::CLASSIFICATIONS.include?(params[:classification])
        @verdicts = @verdicts.where(classification: params[:classification])
      end

      # Confidence filter
      case params[:confidence]
      when "high"
        @verdicts = @verdicts.high_confidence
      when "low"
        @verdicts = @verdicts.low_confidence
      end

      # Scam category filter
      if params[:scam_category].present?
        @verdicts = @verdicts.where(scam_category: params[:scam_category])
      end

      @verdicts = @verdicts.page(params[:page])
    end

    def show
      @associated_domains = @verdict.phish_domains.limit(20)
      @associated_urls = @verdict.phish_urls.limit(20)
    end

    def edit
    end

    def update
      if @verdict.update(verdict_params)
        redirect_to admin_verdict_path(@verdict), notice: "Verdict updated successfully."
      else
        render :edit, status: :unprocessable_entity
      end
    end

    private

    def set_verdict
      @verdict = Verdict.find_by_public_id!(params[:id])
    end

    def verdict_params
      params.require(:verdict).permit(:classification, :confidence_score, :scam_category, :scam_subcategory)
    end
  end
end
