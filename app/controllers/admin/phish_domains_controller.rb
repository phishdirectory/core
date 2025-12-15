# frozen_string_literal: true

module Admin
  class PhishDomainsController < BaseController
    def index
      @domains = Phish::Domain.includes(:verdict)
                              .order(created_at: :desc)
                              .page(params[:page])
    end

    def show
      @domain = Phish::Domain.find(params[:id])
    end
  end
end
