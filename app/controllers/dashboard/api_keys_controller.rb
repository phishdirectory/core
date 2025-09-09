# frozen_string_literal: true

class Dashboard::ApiKeysController < ApplicationController
  before_action :authenticate_user!
  before_action :set_api_key, only: [:show, :destroy]

  def index
    redirect_to dashboard_path
  end

  def new
    @api_key = current_user.user_api_keys.build
  end

  def create
    @api_key = current_user.user_api_keys.build(api_key_params)

    # Set expiration if provided
    if params[:expires_in_days].present?
      days = params[:expires_in_days].to_i
      @api_key.set_expiration(days.days) if days > 0
    end

    if @api_key.save
      @raw_key = @api_key.raw_key
      render :show_new_key
    else
      render :new, status: :unprocessable_entity
    end
  end

  def show
    # Display API key details (without showing the actual key)
  end

  def destroy
    @api_key.destroy!
    redirect_to dashboard_path, notice: "API key '#{@api_key.name}' has been deleted."
  end

  private

  def set_api_key
    @api_key = current_user.user_api_keys.find(params[:id])
  end

  def api_key_params
    params.require(:user_api_key).permit(:name)
  end

end
