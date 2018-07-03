defmodule AlexaRequestVerifierTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AlexaRequestVerifier.CertCache
  alias Plug.Conn

  setup do
    GenServer.call(CertCache, :purge)
    :ok
  end

  test "load, verified cert and test caching " do
    cert_url = "https://s3.amazonaws.com/echo.api/echo-api-cert-6-ats.pem"

    assert capture_log(fn ->
             conn =
               %Conn{}
               |> Conn.put_req_header("signaturecertchainurl", cert_url)
               |> AlexaRequestVerifier.populate_cert()

             cert = conn.private[:signing_cert]
             assert CertCache.get_cert(cert_url) == cert
             refute conn.private[:alexa_verify_error]

             assert AlexaRequestVerifier.populate_cert(conn).private[
                      :signing_cert
                    ] == cert
           end) =~ ~r/caching url/
  end

  test "load, bad cert and test no caching " do
    cert_url = "https://s3.amazonaws.com/echo.api/echo-api-cert.pem"

    assert capture_log(fn ->
             conn =
               %Conn{}
               |> Conn.put_req_header("signaturecertchainurl", cert_url)
               |> AlexaRequestVerifier.populate_cert()

             assert conn.private[:alexa_verify_error]
             assert CertCache.get_cert(cert_url) == nil
           end) =~ ~r/validation error/
  end

  test "load bad cache test " do
    cert_url = "https://s3.amazonaws.com/echo.api/echo-api-cert.pem"

    conn =
      %Conn{}
      |> Conn.put_req_header("signaturecertchainurl", cert_url)
      |> Conn.put_req_header(
        "signature",
        ~s(M4Xq8WmUHjaR4Fgj9HUheoOUkZf4tkc5koBtkBq/nCmh4X6EiimBXWa7) <>
          ~s(p+kHoMx9noTdytGSUREaxYofTne1CzYOW0wxb9x6Jhor6lMwHAr4cY) <>
          ~s(+aR1AEOkWrjsP94bewRr1/CxYNl7kGcj4+QjbEa/7dL19BNmLiufML) <>
          ~s(ZDdRFsZSzlfXpPaAspsoStqVc/qc26tj5R9wtB0sTS4wbFc4eyCPFa) <>
          ~s(CZocq1gmjfR3YQXupuD7J3slrz54SxukNmL/M1CIoZ8lOXjS82XLkK) <>
          ~s(jsrzXdY5ePk8XsEDjNWkFSLbqzBzGBqzWx4M913uDA6gPx5tFKeo) <>
          ~s(P8FgpV+BHKDf3d4gmQ==)
      )
      |> Conn.put_private(:raw_body, "foobar")
      |> AlexaRequestVerifier.verify_signature()

    assert conn.private[:alexa_verify_error]
    assert CertCache.get_cert(cert_url) == nil
  end

  test "load no cert request " do
    conn =
      %Conn{}
      |> AlexaRequestVerifier.populate_cert()

    assert String.contains?(
             conn.private[:alexa_verify_error],
             "no request parameter"
           )
  end

  test "is_datetime_valid tests " do
    refute AlexaRequestVerifier.is_datetime_valid?(nil)
    refute AlexaRequestVerifier.is_datetime_valid?("")
    refute AlexaRequestVerifier.is_datetime_valid?("2016-03-20T19:03:53Z")
    refute AlexaRequestVerifier.is_datetime_valid?("2017-03-20T19:03:53Z")

    assert AlexaRequestVerifier.is_datetime_valid?(
             NaiveDateTime.to_iso8601(NaiveDateTime.utc_now())
           )
  end

  test "valid amazonaws cert url tests" do
    refute AlexaRequestVerifier.is_correct_alexa_url?(nil)
    refute AlexaRequestVerifier.is_correct_alexa_url?("http://www.alexa.com")
    refute AlexaRequestVerifier.is_correct_alexa_url?("hello world")

    refute AlexaRequestVerifier.is_correct_alexa_url?(
             "http://s3.amazonaws.com/echo.api/echo-api-cert.pem"
           )

    refute AlexaRequestVerifier.is_correct_alexa_url?(
             "https://s4.amazonaws.com/bad_bad.api/echo-api-cert.pem"
           )

    refute AlexaRequestVerifier.is_correct_alexa_url?(
             "https://s3.amazonaws.com:12345/echo.api/echo-api-cert.pem"
           )

    refute AlexaRequestVerifier.is_correct_alexa_url?(
             "ftp://s3.amazonaws.com/echo.api/echo-api-cert.pem"
           )

    assert AlexaRequestVerifier.is_correct_alexa_url?(
             "https://s3.amazonaws.com:443/echo.api/echo-api-cert.pem"
           )

    assert AlexaRequestVerifier.is_correct_alexa_url?(
             "https://s3.amazonaws.com/echo.api/echo-api-cert.pem"
           )

    assert AlexaRequestVerifier.is_correct_alexa_url?(
             "https://s3.amazonaws.com/echo.api/echo-api-cert4.pem"
           )

    assert AlexaRequestVerifier.is_correct_alexa_url?(
             "https://s3.amazonaws.com/echo.api/../echo.api/echo-api-cert.pem"
           )
  end

  test "test_mode disables authentication checking" do
    cert_url = "https://www.foobar.com"

    conn =
      %Conn{}
      |> Conn.put_private(:alexa_verify_test_disable, true)
      |> Conn.put_req_header("signaturecertchainurl", cert_url)
      |> AlexaRequestVerifier.call(%{})

    refute conn.private[:alexa_verify_error]
  end
end
