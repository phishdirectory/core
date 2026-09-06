# frozen_string_literal: true

module Admin
  class ProtectionsController < BaseController
    before_action :set_protection, only: [ :show, :destroy ]

    def index
      @protections = Phish::Protection.kept
                                      .includes(:protected_by)
                                      .order(created_at: :desc)
                                      .page(params[:page])

      @filter = params[:type]
      @protections = @protections.for_domains if @filter == "domain"
      @protections = @protections.for_urls if @filter == "url"
    end

    def show
    end

    def new
      @protection = Phish::Protection.new
      @protection.protectable_type = params[:type] || "Phish::Domain"
    end

    def create
      @protection = Phish::Protection.new(protection_params)
      @protection.protected_by = current_user

      if @protection.save
        redirect_to admin_protections_path, notice: "Protection added successfully."
      else
        render :new, status: :unprocessable_entity
      end
    end

    def destroy
      @protection.discard!
      redirect_to admin_protections_path, notice: "Protection removed."
    end

    private

    def set_protection
      @protection = Phish::Protection.find_by_public_id!(params[:id])
    end

    def protection_params
      params.require(:phish_protection).permit(:protectable_type, :protectable_value, :reason)
    end
  end
end
