# frozen_string_literal: true

module Admin
  class PhishPhoneNumbersController < BaseController
    def index
      @phone_numbers = Phish::PhoneNumber.includes(:verdict, :carrier)
                                         .order(created_at: :desc)
                                         .page(params[:page])
    end

    def show
      @phone_number = Phish::PhoneNumber.find_by_public_id!(params[:id])
    end
  end
end
