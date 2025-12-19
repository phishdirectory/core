# frozen_string_literal: true

module Dashboard
  class ApiKeysController < BaseController
    before_action :set_api_key, only: [:destroy, :regenerate]

    def index
      @api_keys = current_user.user_api_keys.order(created_at: :desc)
    end

    def create
      @api_key = current_user.user_api_keys.new(api_key_params)

      if @api_key.save
        # Flash the plaintext key since it's only available now
        flash[:api_key] = @api_key.plaintext_key
        redirect_to dashboard_api_keys_path, notice: "API key created. Copy it now - you won't see it again!"
      else
        redirect_to dashboard_api_keys_path, alert: "Failed to create API key: #{@api_key.errors.full_messages.join(', ')}"
      end
    end

    def destroy
      @api_key.destroy
      redirect_to dashboard_api_keys_path, notice: "API key deleted."
    end

    def regenerate
      # Revoke old key
      @api_key.revoke!

      # Create new key with same name
      new_key = current_user.user_api_keys.create!(name: @api_key.name)

      flash[:api_key] = new_key.plaintext_key
      redirect_to dashboard_api_keys_path, notice: "API key regenerated. Copy it now - you won't see it again!"
    end

    private

    def set_api_key
      @api_key = current_user.user_api_keys.find_by_public_id!(params[:id])
    end

    def api_key_params
      params.require(:api_key).permit(:name, :expires_at)
    end
  end
end
