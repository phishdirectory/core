# frozen_string_literal: true

class UsersController < ApplicationController
  before_action :redirect_if_authenticated, only: [:new, :create]
  before_action :authenticate_user!, only: [:show, :edit, :update, :sessions]
  before_action :set_user, only: [:show, :edit, :update, :sessions]
  before_action :authorize_user!, only: [:edit, :update]

  # GET /signup
  def new
    @user = User.new
  end

  # POST /signup
  def create
    @user = User.new(signup_params)

    if @user.save
      # Send magic link for first login instead of auto-signing in
      @user.send_magic_link
      redirect_to login_path, notice: "Account created! Check your email for a magic link to sign in."
    else
      render :new, status: :unprocessable_entity
    end
  end

  # GET /users/:id
  def show
    unless @user.viewable_by?(current_user) || @user == current_user
      redirect_to root_path, alert: "You don't have permission to view this profile."
    end
  end

  # GET /users/:id/edit
  def edit
  end

  # PATCH/PUT /users/:id
  def update
    if @user.update(user_params)
      redirect_to user_path(@user), notice: "Profile updated successfully."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  # GET /users/:id/sessions
  def sessions
    @sessions = @user.user_sessions.order(created_at: :desc)
  end

  private

  def set_user
    @user = User.find_by_public_id!(params[:id])
  end

  def authorize_user!
    unless @user == current_user || current_user.admin?
      redirect_to root_path, alert: "You can only edit your own profile."
    end
  end

  def redirect_if_authenticated
    redirect_to dashboard_root_path if user_signed_in?
  end

  def signup_params
    params.require(:user).permit(:first_name, :last_name, :email)
  end

  def user_params
    params.require(:user).permit(:first_name, :last_name, :profile_photo)
  end
end
