defmodule Ueberauth.Strategy.Core do
  @moduledoc """
  Ueberauth strategy for "Core"
  """
  use Ueberauth.Strategy, default_scope: "default profile"

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  # Handle_request > [DO AUTHORIZATION] > handle_callback > [GET TOKEN] > fetch_user

  def handle_request!(conn) do
    opts =
      [scope: "default profile"] |> Keyword.put(:redirect_uri, callback_url(conn))

    redirect!(conn, Ueberauth.Strategy.Core.OAuth.authorize_url!(opts))
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn)]
    token = Ueberauth.Strategy.Core.OAuth.get_token!([code: code], opts)

    if token.access_token == nil do
      set_errors!(conn, [error(token.other_params["error"], token.other_params["error_description"])])
    else
      fetch_user(conn, token)
    end
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:core_user, nil)
    |> put_private(:core_token, nil)
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :core_token, token)

    path = "http://localhost:4001/oauth/v1/userinfo"
    resp = Ueberauth.Strategy.Core.OAuth.get(token, path)

    case resp do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: status_code, body: user}} when status_code in 200..399 ->
        put_private(conn, :core_user, user)
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  def credentials(conn) do
    token        = conn.private.core_token
    scope_string = (token.other_params["scope"] || "")
    scopes       = String.split(scope_string)

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  def info(conn) do
    user = conn.private.core_user

    %Info{
      email: user["email"]
    }
  end

  def uid(conn) do
    conn.private.core_user["coreid"]
  end

  @doc """
  Stores the raw information (including the token) obtained from the core callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.core_token,
        user: conn.private.core_user
      }
    }
  end

  defp with_param(opts, key, conn) do
    if value = conn.params[to_string(key)], do: Keyword.put(opts, key, value), else: opts
  end

  defp with_optional(opts, key, conn) do
    if option(conn, key), do: Keyword.put(opts, key, option(conn, key)), else: opts
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end