# frozen_string_literal: true

module Admin
  class ServiceKeysController < BaseController
    before_action :set_service
    before_action :set_key, only: [:destroy, :deprecate, :revoke]

    def index
      @keys = @service.service_keys.order(created_at: :desc)
    end

    def create
      @key = @service.generate_key!(notes: params[:notes])
      redirect_to admin_service_path(@service), notice: "API key created: #{@key.api_key}"
    rescue ActiveRecord::RecordInvalid => e
      redirect_to admin_service_path(@service), alert: "Failed to create key: #{e.message}"
    end

    def destroy
      @key.destroy
      redirect_to admin_service_path(@service), notice: "Key deleted."
    end

    def deprecate
      if @key.may_deprecate?
        @key.deprecate!
        redirect_to admin_service_path(@service), notice: "Key deprecated."
      else
        redirect_to admin_service_path(@service), alert: "Cannot deprecate this key."
      end
    end

    def revoke
      if @key.may_revoke?
        @key.revoke!
        redirect_to admin_service_path(@service), notice: "Key revoked."
      else
        redirect_to admin_service_path(@service), alert: "Cannot revoke this key."
      end
    end

    private

    def set_service
      @service = Service.find(params[:service_id])
    end

    def set_key
      @key = @service.service_keys.find(params[:id])
    end
  end
end
