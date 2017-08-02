Links::Application.routes.draw do
  resource :session
  resources :users
  resources :links
  resources :comments
end
