# frozen_string_literal: true

module Api
  module V1
    module Domain
      class ProtectionsController < BaseController
        before_action :require_admin!
        before_action :set_protection, only: [:show, :destroy]

        # GET /api/v1/domain/protections
        def index
          protections = Phish::Protection.for_domains.kept.recent

          render json: {
            protections: protections.map { |p| serialize_protection(p) },
            count: protections.size
          }
        end

        # GET /api/v1/domain/protections/:id
        def show
          render json: serialize_protection(@protection)
        end

        # POST /api/v1/domain/protections
        def create
          protection = Phish::Protection.new(protection_params)
          protection.protectable_type = "Phish::Domain"
          protection.protected_by = current_user

          if protection.save
            render json: serialize_protection(protection), status: :created
          else
            render json: { errors: protection.errors.full_messages }, status: :unprocessable_entity
          end
        end

        # DELETE /api/v1/domain/protections/:id
        def destroy
          @protection.discard!
          head :no_content
        end

        private

        def set_protection
          @protection = find_by_public_or_uuid!(Phish::Protection, params[:id], prefix: "prt")
        end

        def protection_params
          params.permit(:protectable_value, :reason)
        end

        def serialize_protection(protection)
          {
            id: protection.public_id,
            domain: protection.protectable_value,
            reason: protection.reason,
            protected_by: protection.protected_by.public_id,
            created_at: protection.created_at.iso8601
          }
        end

        def require_admin!
          return if current_user&.admin?

          render json: { error: "Admin access required" }, status: :forbidden
        end
      end
    end
  end
end
