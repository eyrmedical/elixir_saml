defmodule ElixirSAML.Conditions do
  @moduledoc false

  import SweetXml, only: [xpath: 2, sigil_x: 2]
  require Logger

  @latency_compensation Application.get_env(:elixir_saml, :latency_compensation, 0)

  defstruct not_before: "",
            not_on_or_after: "",
            audience_restrictions: []

  @doc """
  Check that current date is within `<Conditions NotBefore="date" NotOnOrAfter="date" />`.

  Set `latency_compensation: 5` in config to set the recommended 5 seconds.
  """
  def verify_date(
        %ElixirSAML.Conditions{not_before: not_before, not_on_or_after: not_on_or_after},
        now \\ DateTime.utc_now()
      ) do
    # Adds the recommended latency compensation (5 seconds)
    now = Map.put(now, :seconds, now.second + @latency_compensation)

    result =
      case {DateTime.compare(now, not_before), DateTime.compare(now, not_on_or_after)} do
        {:gt, :lt} ->
          {:ok, "Date check passed"}

        {:lt, _} ->
          {:error, "Server time is before the SAML NotBefore date"}

        {_, :gt} ->
          {:error, "Server time is after the SAML NotBefore date"}

        {_, :eq} ->
          {:error, "Server time is equal to the SAML NotOnOrAfter"}

        _ ->
          {:error, "Invalid dates passed to SAML Conditions"}
      end

    if elem(result, 0) === :error do
      Logger.error(fn ->
        """

        #{elem(result, 1)}

        SAML not before:     	#{DateTime.to_string(not_before)}
        Server time:       		#{DateTime.to_string(now)}
        SAML not on or after:  	#{DateTime.to_string(not_on_or_after)}

        The SAML response timestamp is inconsistent with server time.

        If you see this error in production you should lax the latency
        compensation in config, although it is recommended to keep it at
        5 seconds or lower.

        If you see this error in development the most common cause is that
        the time of your docker container has drifted, which can happen if
        your computer is sleeping.
        """
      end)
    end

    result
  end

  @doc """
  Verify the condition audience restrictions
  """
  def verify_audience(%ElixirSAML.Conditions{audience_restrictions: _} = conditions, nil) do
    {:ok, conditions}
  end

  def verify_audience(
        %ElixirSAML.Conditions{audience_restrictions: restrictions} = conditions,
        audience
      ) do
    case audience in restrictions do
      true -> {:ok, conditions}
      false -> {:error, "Invalid audience: #{audience} is not in restricted audiences"}
    end
  end

  @doc """
  Parse the conditions statement into `%ElixirSAML.Conditions{}`
  """
  def parse(xml) do
    with {:ok, not_before, _} =
           xpath(xml, ~x"//Conditions/@NotBefore") |> to_string |> DateTime.from_iso8601(),
         {:ok, not_on_or_after, _} =
           xpath(xml, ~x"//Conditions/@NotOnOrAfter") |> to_string |> DateTime.from_iso8601(),
         audience_restrictions =
           xpath(xml, ~x"//Conditions/AudienceRestrictionCondition/Audience/text()"l)
           |> Enum.map(&to_string(&1)) do
      {:ok,
       %ElixirSAML.Conditions{
         not_before: not_before,
         not_on_or_after: not_on_or_after,
         audience_restrictions: audience_restrictions
       }}
    else
      _ -> {:error, "Invalid SAML Response"}
    end
  end

  def parse!(xml) do
    case parse(xml) do
      {:ok, %ElixirSAML.Conditions{} = conditions} -> conditions
      _ -> :error
    end
  end
end
