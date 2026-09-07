# frozen_string_literal: true

module Admin
  class ServiceKeysController < BaseController
    before_action :set_service
    before_action :set_key, only: [ :destroy, :deprecate, :revoke, :trust, :untrust ]

    def index
      @keys = @service.service_keys.order(created_at: :desc)
    end

    def create
      trusted_source = params[:trusted_source] == "1"

      if trusted_source && !current_user.superadmin?
        return redirect_to admin_service_path(@service),
                           alert: "Only superadmins can issue a trusted source key."
      end

      @key = @service.generate_key!(notes: params[:notes], trusted_source: trusted_source)
      # The plaintext is never stored, so this is the only time it can be shown.
      redirect_to admin_service_path(@service),
                  notice: "API key created. Copy it now, it cannot be shown again: #{@key.plaintext_key}"
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

    # A trusted source key writes verdicts straight into the database through
    # Api::V1::Source::EntriesController, so this is a privilege grant and not a
    # display setting. Admin::UsersController#promote draws the same line: a
    # plain admin does not hand out powers it does not itself hold.
    def trust
      unless current_user.superadmin?
        return redirect_to admin_service_path(@service),
                           alert: "Only superadmins can mark a key as a trusted source."
      end

      @key.mark_trusted_source!
      redirect_to admin_service_path(@service), notice: "Key marked as a trusted source."
    end

    # Withdrawing the grant is open to any admin. Taking a write privilege away
    # can only reduce risk, and an admin who spots a source misbehaving should
    # not have to find a superadmin before they can stop it.
    def untrust
      @key.unmark_trusted_source!
      redirect_to admin_service_path(@service), notice: "Key is no longer a trusted source."
    end

    private

    def set_service
      @service = Service.find_by_public_id!(params[:service_id])
    end

    def set_key
      @key = @service.service_keys.find_by_public_id!(params[:id])
    end
  end
end
