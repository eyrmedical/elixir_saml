# Bankid

A BankID authentication cycle happens like this:

1. The user goes to a sign-in page. (client)
2. User clicks 'Sign in with BankID'
  * A UID `credential_token` is generated and stored in client
  * A new window is opened with URL  `<BANKID_URL>?target=<SERVER_URL>/auth/bankid/<credential_token>`.
    * Example: [https://preprod.signicat.com/std/method/demo?id=nbid:iframe:nb&target=https://app.eyrstaging.com/auth/bankid/QWE123QWE123](https://preprod.signicat.com/std/method/demo?id=nbid:iframe:nb&target=https://app.eyrstaging.com/auth/bankid/QWE123QWE123) (client)
  * The client also adds a listener to check if the window still exists
  * Signicat handles the authentication cycle. User enters some information, example (usable for testing):
    1. `01018080010`
    2. `otp`
    3. `qwer1234`
  * Upon successful authentication user is redirected to `target` address from the URL
3. The web server recieves a call to ``/auth/bankid/<credential_token>`` with a body that contains a SAML object as a `base64` string.
  * decode string
  * parse XML (extract `<Signature`> and `<Assertion>`)
  * verify `<Signature`> towards a certificated stored on server
  * verify contents of `<Conditions>`
  * if verified - extract user information from `<Assertion>`
  * if no user - create new user
  * send a callback to close the window
  * Store a reference in memory that the `credential_token` has been validated for 10 seconds.
4. The window is closed and the listener from pt.2 will detect it.
  * The client can now assume that a reference to it's `credential_token` has been stored.
  * The client calls login with `{ saml: true, credential_token }`
5. Server recieves login call with reference to `credential_token`
  * Server searches through references, if matching the login call is successful and the user/client is issued a token



## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add `bankid` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:bankid, "~> 0.1.0"}]
    end
    ```

  2. Ensure `bankid` is started before your application:

    ```elixir
    def application do
      [applications: [:bankid]]
    end
    ```
