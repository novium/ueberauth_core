defmodule Ueberauth.Strategy.Core.OAuth do
  @moduledoc false
  use OAuth2.Strategy

  @defaults [
     strategy: __MODULE__,
     site: "http://localhost:4001",
     authorize_url: "http://localhost:4001/oauth/v1/authorize",
     token_url: "http://core:4001/oauth/v1/token"
  ]


  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Core.OAuth)
    conf =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)
    OAuth2.Client.new(conf)
  end

  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_token!(params \\ [], opts \\ []) do
    client =
      opts
      |> client()
      |> OAuth2.Client.get_token!(params)
    client.token
  end

  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client.client_secret)
    |> put_param("client_id", client.client_id)
    |> put_param("grant_type", "authorization_code")
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end
end