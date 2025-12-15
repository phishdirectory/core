# frozen_string_literal: true

module Admin
  class PhishUrlsController < BaseController
    def index
      @urls = Phish::Url.includes(:verdict)
                        .order(created_at: :desc)
                        .page(params[:page])
    end

    def show
      @url = Phish::Url.find(params[:id])
    end
  end
end
