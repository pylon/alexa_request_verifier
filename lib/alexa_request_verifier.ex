defmodule AlexaRequestVerifier do
  @moduledoc """
  AlexaRequestVerifier verifies an Amazon Alexa Skills request to a
  Phoenix server.

  There are two options for verifying a request: Manually and automatically.

  To automatically verify the request using the verifier as a plug, you will
  need to make 3 changes:

  1. You will need to add AlexaRequestVerifier as an application in `mix.exs`

  ```elixir
      applications: [..., :pylon_alexa_request_verifier]
  ```

  2.  You will need to modify your `endpoint.ex` file by adding the
      JSONRawBodyParser as follows:

  ```elixir
      parsers: [AlexaRequestVerifier.JSONRawBodyParser, :urlencoded,
                :multipart, :json],
  ```

  The parser is needed to collect the raw body of the request as that is needed
  to verify the signature.

  3. You will need to add the verifier plug to your pipeline in your
     router.ex file:

  ```elixir
  pipeline :alexa_api do
      plug :accepts, ["json"]
      plug AlexaRequestVerifier
  end
  ```
  """

  alias AlexaRequestVerifier.CertCache
  alias Plug.Conn

  require Logger

  @amazon_echo_dns "echo-api.amazon.com"
  @sig_header "signature"
  @sig_chain_header "signaturecertchainurl"

  def init(opts), do: opts

  def call(conn, _opts) do
    case conn.private[:alexa_verify_test_disable] do
      true ->
        conn

      _ ->
        conn = verify_request(conn)

        if conn.private[:alexa_verify_error] do
          Logger.debug(
            "alexa_request_verifier error",
            error: conn.private[:alexa_verify_error]
          )

          conn
          |> Conn.send_resp(401, conn.private[:alexa_verify_error])
          |> Conn.halt()
        else
          conn
        end
    end
  end

  @doc """
  Run all functions required to verify an incoming request as originating
  from Amazon, storing an error message in the connection's private params
  if validation fails.
  """
  @spec verify_request(conn :: Conn.t()) :: Conn.t()
  def verify_request(conn) do
    conn
    |> populate_cert()
    |> verify_time()
    |> verify_signature()
  end

  @doc """
  Retrieve a valid Amazon certificate, either from the cache or
  from source, and store it in the connection's private params.
  """
  @spec populate_cert(conn :: Conn.t()) :: Conn.t()
  def populate_cert(conn) do
    case Conn.get_req_header(conn, @sig_chain_header) do
      [] ->
        Conn.put_private(
          conn,
          :alexa_verify_error,
          "no request parameter named #{@sig_chain_header}"
        )

      [cert_url] ->
        cert_url = cert_url

        cert = CertCache.get_cert(cert_url)

        if is_nil(cert) do
          cert = fetch_cert(cert_url)

          case validate_cert(cert) do
            {:ok, _} ->
              Logger.debug(
                "alexa_request_verifier: caching url",
                cert_url: cert_url
              )

              CertCache.store(cert_url, cert)
              Conn.put_private(conn, :signing_cert, cert)

            {:error, reason} ->
              Logger.debug(
                "alexa_request_verifier validation error",
                validation_error: reason
              )

              Conn.put_private(conn, :alexa_verify_error, reason)
          end
        else
          Conn.put_private(conn, :signing_cert, cert)
        end
    end
  end

  defp fetch_cert(url) do
    if is_correct_alexa_url?(url) do
      {:ok, resp} =
        :httpc.request(
          :get,
          {String.to_charlist(url), []},
          [],
          body_format: :binary
        )

      {_, _headers, certificate_chain_bin} = resp
      cert_chain = :public_key.pem_decode(certificate_chain_bin)

      Enum.map(
        cert_chain,
        fn {_, bin, _} -> bin end
      )
    else
      {:error, "invalid sig chain url"}
    end
  end

  @doc """
  Determines whether a request URL represents a valid
  Alexa request.
  """
  @spec is_correct_alexa_url?(url :: String.t() | URI.t()) :: boolean
  def is_correct_alexa_url?(url) when is_binary(url) do
    is_correct_alexa_url?(URI.parse(url))
  end

  def is_correct_alexa_url?(url) when is_nil(url) do
    false
  end

  def is_correct_alexa_url?(%URI{
        port: 443,
        host: "s3.amazonaws.com",
        scheme: "https",
        path: "/echo.api/" <> _extra
      }) do
    true
  end

  def is_correct_alexa_url?(_everything_else) do
    false
  end

  defp validate_cert({:error, _reason} = err) do
    err
  end

  defp validate_cert(cert) do
    cert
    |> validate_cert_chain()
    |> validate_cert_domain()
  end

  defp validate_cert_chain(cert) do
    reversed = Enum.reverse(cert)
    roots = :certifi.cacerts()

    if validate_unordered(reversed, roots) do
      {:ok, cert}
    else
      {:error, "no valid root found"}
    end
  end

  defp validate_unordered([], _), do: true

  defp validate_unordered(untrusted, trusted) do
    # we can't always assume that Amazon will give us their certs in order;
    # the iteration is performed with a reversed list of the incoming
    # certificates in the hope that it will be, but this ensures validation
    # even if the chain is out of order
    valid =
      Enum.find(
        untrusted,
        fn cert -> Enum.find(trusted, &validate_root(&1, cert)) end
      )

    if valid do
      untrusted
      |> List.delete(valid)
      |> validate_unordered([valid | trusted])
    else
      false
    end
  end

  defp validate_root(root, cert) do
    case :public_key.pkix_path_validation(
           root,
           [cert],
           verify_fun: {&verify_fun/3, {}}
         ) do
      {:ok, {_public_key_info, _policy_tree}} -> true
      {:error, {:bad_cert, _reason}} -> false
    end
  end

  @doc """
  Verify function sent to Erlang's :public_key module for path validation.
  """
  @spec verify_fun(cert :: map, event :: {atom, atom | map}, state :: term()) ::
          {atom, any}
  def verify_fun(_cert, {:extension, _}, state) do
    {:unknown, state}
  end

  def verify_fun(_cert, {:bad_cert, reason}, _state) do
    {:fail, reason}
  end

  def verify_fun(_cert, {:revoked, _}, _state) do
    {:fail, :revoked}
  end

  def verify_fun(_cert, _event, state) do
    {:unknown, state}
  end

  defp validate_cert_domain({:error, _reason} = error) do
    error
  end

  defp validate_cert_domain({:ok, cert}) do
    [first | _tail] = cert

    if :public_key.pkix_verify_hostname(first, [{:dns_id, @amazon_echo_dns}]) do
      {:ok, cert}
    else
      {:error, "invalid DNS"}
    end
  end

  @doc """
    given a Plug.Conn that has a valid Alexa request request/timestamp,
    confirms that the timestamp is valid
  """
  @spec verify_time(conn :: Conn.t()) :: Conn.t()
  def verify_time(conn) do
    params = conn.body_params
    timestamp = params["request"]["timestamp"]

    case is_datetime_valid?(timestamp) do
      true ->
        conn

      false ->
        Conn.put_private(conn, :alexa_verify_error, "invalid timestamp")
    end

    conn
  end

  @doc """
  Determines if a request's timestamp is valid.
  """
  @spec is_datetime_valid?(datetime :: String.t() | NaiveDateTime.t() | nil) ::
          boolean
  def is_datetime_valid?(datetime) when is_nil(datetime), do: false

  def is_datetime_valid?(datetime_string) when is_binary(datetime_string) do
    case NaiveDateTime.from_iso8601(datetime_string) do
      {:ok, datetime} ->
        is_datetime_valid?(datetime)

      {:error, _reason} ->
        false
    end
  end

  def is_datetime_valid?(%NaiveDateTime{} = datetime) do
    # minimum number of seconds
    min = 150
    NaiveDateTime.diff(NaiveDateTime.utc_now(), datetime, :second) <= min
  end

  @doc """
    Assuming :raw_body, :signing_cert, and signature header,
    verifies the signature
  """
  @spec verify_signature(conn :: Conn.t()) :: Conn.t()
  def verify_signature(conn) do
    case conn.private[:signing_cert] do
      nil ->
        Conn.put_private(conn, :alexa_verify_error, "invalid certificate")

      _ ->
        verify_signature_with_valid_cert(conn)
    end
  end

  defp verify_signature_with_valid_cert(conn) do
    message = conn.private[:raw_body]

    case Conn.get_req_header(conn, @sig_header) do
      [] ->
        Conn.put_private(conn, :alexa_verify_error, "no signature")

      [signature] ->
        {:ok, signature} = Base.decode64(signature)
        [first | _tail] = conn.private[:signing_cert]
        decoded = :public_key.pkix_decode_cert(first, :otp)
        public_key_der = decoded |> elem(1) |> elem(7) |> elem(2)

        if !is_nil(public_key_der) &&
             :public_key.verify(message, :sha, signature, public_key_der) do
          conn
        else
          Conn.put_private(conn, :alexa_verify_error, "signature did not match")
        end
    end
  end
end
