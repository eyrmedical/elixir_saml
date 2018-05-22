defmodule SAML.Signature do
    @moduledoc """
    Extract user data from SAML conditions into a structured response
    """
    defstruct \
        uid: "",
        national_id: "",
        first_name: "",
        last_name: "",
        date_of_birth: "",
        gender: "",
        origin: nil
end