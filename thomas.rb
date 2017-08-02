










































class User < ActiveRecord::Base
  validates :username, :password_digest, :session_token, presence: true
  validates :password, length: { minimum: 6, allow_nil: true }

  attr_reader :password

  has_many :links
  has_many :comments

  after_initialize :ensure_session_token

  def self.find_by_credentials(username, password)
    user = User.find_by(username: username)
    return nil unless user && user.valid_password?(password)
    user
  end

  def password=(password)
    @password = password
    self.password_digest = BCrypt::Password.create(password)
  end

  def valid_password?(password)
    BCrypt::Password.new(self.password_digest).is_password?(password)
  end

  def reset_token!
    self.session_token = SecureRandom.urlsafe_base64(16)
    self.save!
    self.session_token
  end

  private
  def ensure_session_token
    self.session_token ||= SecureRandom.urlsafe_base64(16)
  end
end

class Link < ActiveRecord::Base
  validates :title, :url, :user, presence: true

  belongs_to :user,
    class_name: "User",
    foreign_key: :user_id,
    primary_key: :id

  has_many :comments,
    class_name: "Comment",
    foreign_key: :link_id,
    primary_key: :id
end

class Comment < ActiveRecord::Base
  validates :body, :link, :user, presence: true

  belongs_to :user
  belongs_to :link
end

module ApplicationHelper
  # Make your life easier,
  # define the CSRF auth token in a helper
  # and put it in all the forms!
  def auth_token_input
    "<input
        type=\"hidden\"
        name=\"authenticity_token\"
        value=\"#{ form_authenticity_token }\">".html_safe
  end
end


class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  # Expose these methods to the views
  helper_method :current_user, :signed_in?

  private
  def current_user
    @current_user ||= User.find_by_session_token(session[:session_token])
  end

  def signed_in?
    !!current_user
  end

  def sign_in(user)
    @current_user = user
    session[:session_token] = user.reset_token!
  end

  def sign_out
    current_user.try(:reset_token!)
    session[:session_token] = nil
  end

  def require_signed_in!
    redirect_to new_session_url unless signed_in?
  end
end


class UsersController < ApplicationController
  def new
    @user = User.new
  end

  def create
    @user = User.new(user_params)

    if @user.save
      sign_in(@user)
      redirect_to links_url
    else
      flash.now[:errors] = @user.errors.full_messages
      render :new
    end
  end

  private
  def user_params
    params.require(:user).permit(:password, :username)
  end
end



class SessionsController < ApplicationController
  def new
  end

  def create
    user = User.find_by_credentials(
      params[:user][:username],
      params[:user][:password]
    )

    if user
      sign_in(user)
      redirect_to links_url
    else
      flash.now[:errors] = ["Invalid username or password"]
      render :new
    end
  end

  def destroy
    sign_out
    redirect_to new_session_url
  end


end



class LinksController < ApplicationController
  before_filter :require_signed_in!

  def index
    @links = Link.all
  end

  def show
    @link = Link.find(params[:id])
  end

  def new
    @link = Link.new
  end

  def create
    @link = Link.new(link_params)
    @link.user_id = current_user.id
    if @link.save
      redirect_to link_url(@link)
    else
      flash.now[:errors] = @link.errors.full_messages
      render :new
    end
  end

  def edit
    @link = Link.find(params[:id])
  end

  def update
    @link = current_user.links.find(params[:id])
    if @link.update_attributes(link_params)
      redirect_to link_url(@link)
    else
      flash.now[:errors] = @link.errors.full_messages
      render :edit
    end
  end

  def destroy
    link = Link.find(params[:id])
    link.destroy
    redirect_to links_url
  end

  private
  def link_params
    params.require(:link).permit(:title, :url)
  end
end


class CommentsController < ApplicationController
  before_filter :require_signed_in!

  def create
    comment = Comment.new(comment_params)
    comment.user_id = current_user.id
    comment.save
    flash[:errors] = comment.errors.full_messages
    redirect_to link_url(comment.link)
  end

  def destroy
    comment = Comment.find(params[:id])
    comment.destroy
    redirect_to link_url(comment.link_id)
  end

  private
  def comment_params
    params.require(:comment).permit(:body, :link_id)
  end
end


views>links>edit.html.erb
<h2>Edit Link</h2>

<form action="<%= link_url(@link) %>" method="post">
  <%= auth_token_input %>
  <input type="hidden" name="_method" value="patch">

  <label>
    Title
    <input type="text" name="link[title]" value="<%= @link.title %>">
  </label>

  <label>
    URL
    <input type="text" name="link[url]" value="<%= @link.url %>">
  </label>

  <input type="submit" value="Update Link">
</form>






views>links>index.html.erb
<h1>Links</h1>

<ul>
  <% @links.each do |link|%>
    <li><%= link_to link.title, link_url(link) %> : <%= link.url %></li>
  <% end %>
</ul>

<%= link_to "New Link", new_link_url %>




views>links>new.html.erb


<h2>New Link</h2>

<form action="<%= links_url %>" method="post">
  <%= auth_token_input %>

  <label>
    Title
    <input type="text" name="link[title]" value="<%= @link.title %>" id="title">
  </label>

  <label>
    URL
    <input type="text" name="link[url]" value="<%= @link.url %>" id="url">
  </label>

  <input type="submit" value="Create New Link">
</form>




views>links>show.html.erb

<h2><%= @link.title %></h2>
By: <%= @link.user.username %>

<%= link_to @link.url, @link.url %>


<h3>Comments</h3>
<ul>
  <% @link.comments.each do |comment| %>
    <li>
      <%= comment.body %>
      <%= button_to "Remove Comment", comment_url(comment), method: :delete %>
    </li>
  <% end %>
</ul>

<hr>

<h3>Add Comment</h3>

<form action="<%= comments_url %>" method="post">
  <%= auth_token_input %>

  <input type="hidden" name="comment[link_id]" value="<%= @link.id %>">
  <label>
    Comment
    <input type="text" name="comment[body]" value="">
  </label>
  <input type="submit" value="Add Comment">
</form>
<%= link_to "Edit Link", edit_link_url(@link) %>
<%= link_to "Links", links_url %>





views>sessions>new.html.erb

<h2>Sign In</h2>

<form action="<%= session_url %>" method="post">
  <%= auth_token_input %>

  <label for="user_username">
    Username</label>
    <input type="text" name="user[username]" value="" id="user_username">


  <label>
    Password
    <input type="password" name="user[password]" value="">
  </label>

  <input type="submit" value="Sign In">
</form>




views>sessions>new.html.erb

<h2>Sign Up</h2>

<form action="<%= users_url %>" method="post">
  <%= auth_token_input %>
  <label>
    Username
    <input type="text" name="user[username]" value="">
  </label>

  <label>
    Password
    <input type="password" name="user[password]" value="">
  </label>

  <input type="submit" value="Sign Up">
</form>


routes

Links::Application.routes.draw do
  root to: "sessions#new"

  resources :users, only: [:new, :create]
  resource :session, only: [:new, :create, :destroy]
  resources :links
  resources :comments, only: [:create, :destroy]
end
