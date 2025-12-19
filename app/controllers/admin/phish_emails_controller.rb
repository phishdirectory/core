# frozen_string_literal: true

module Admin
  class PhishEmailsController < BaseController
    def index
      @emails = Phish::Email.includes(:verdict)
                            .order(created_at: :desc)
                            .page(params[:page])
    end

    def show
      @email = Phish::Email.find_by_public_id!(params[:id])
    end
  end
end
