# frozen_string_literal: true

class Admin::UserApiKeysController < Admin::BaseController
  before_action :set_user
  before_action :set_api_key, only: [:show, :destroy]

  def index
    @api_keys = @user.user_api_keys.order(created_at: :desc)
  end

  def show
  end

  def new
    @api_key = @user.user_api_keys.build
  end

  def create
    @api_key = @user.user_api_keys.build(api_key_params)

    # Set expiration if provided
    if params[:expires_in_days].present?
      days = params[:expires_in_days].to_i
      @api_key.set_expiration(days.days) if days > 0
    end

    if @api_key.save
      # Store the raw key to show it once
      @raw_key = @api_key.raw_key
      render :show_new_key
    else
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    @api_key.destroy!
    redirect_to admin_user_user_api_keys_path(@user), notice: "API key deleted successfully."
  end

  private

  def set_user
    @user = User.find(params[:user_pd_id])
  end

  def set_api_key
    @api_key = @user.user_api_keys.find(params[:id])
  end

  def api_key_params
    params.require(:user_api_key).permit(:name)
  end

end
