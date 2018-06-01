defmodule ElixirSAML.AuthenticationRequest do
  @moduledoc """
  Create an authentication request with the following data:
  * `uid` - string, optional internal identifier
  * `csrf_token` - string, optional Elixir Phoenix (or similiar) CSRF token
  * `server_url` - string, optional server URL to return the authentication response to
  * `audience_url` - string, optional audience url reference to check in conditions statement
  * `authentication_method` - atom, one of `[:bankid, :nemid]`
  """

  defstruct uid: "",
            csrf_token: "",
            server_url: "",
            audience: nil,
            adapter: nil,
            authentication_method: nil
end
