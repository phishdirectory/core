# frozen_string_literal: true

module Admin
  class ServicesController < BaseController
    before_action :set_service, except: [:index, :new, :create]

    def index
      @services = Service.order(created_at: :desc).page(params[:page])
    end

    def show
      @keys = @service.service_keys.order(created_at: :desc)
      @webhooks = @service.service_webhooks
    end

    def new
      @service = Service.new
    end

    def create
      @service = Service.new(service_params)

      if @service.save
        redirect_to admin_service_path(@service), notice: "Service created successfully."
      else
        render :new, status: :unprocessable_entity
      end
    end

    def edit
    end

    def update
      if @service.update(service_params)
        redirect_to admin_service_path(@service), notice: "Service updated successfully."
      else
        render :edit, status: :unprocessable_entity
      end
    end

    def destroy
      if @service.destroy
        redirect_to admin_services_path, notice: "Service deleted."
      else
        redirect_to admin_service_path(@service), alert: "Unable to delete service."
      end
    end

    def suspend
      if @service.may_suspend?
        @service.suspend!
        redirect_to admin_service_path(@service), notice: "Service suspended."
      else
        redirect_to admin_service_path(@service), alert: "Cannot suspend this service."
      end
    end

    def reactivate
      if @service.may_reactivate?
        @service.reactivate!
        redirect_to admin_service_path(@service), notice: "Service reactivated."
      else
        redirect_to admin_service_path(@service), alert: "Cannot reactivate this service."
      end
    end

    def decommission
      if @service.may_decommission?
        @service.decommission!
        redirect_to admin_service_path(@service), notice: "Service decommissioned."
      else
        redirect_to admin_service_path(@service), alert: "Cannot decommission this service."
      end
    end

    private

    def set_service
      @service = Service.find_by_public_id!(params[:id])
    end

    def service_params
      params.require(:service).permit(:name)
    end
  end
end
