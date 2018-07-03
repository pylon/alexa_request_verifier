defmodule AlexaRequestVerifier.Mixfile do
  use Mix.Project

  def project do
    [
      app: :pylon_alexa_request_verifier,
      version: "0.1.6",
      elixir: "~> 1.6",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      dialyzer: [ignore_warnings: ".dialyzerignore"]
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [
      extra_applications: [:logger, :inets],
      mod: {AlexaRequestVerifier.Application, []}
    ]
  end

  defp description do
    """
    The Pylon Alexa Request Verifier is an updated fork of the
    alexa_request_verifier library designed to handle all certificate and
    request verification for Alexa skills.
    (See the Alexa Skills Documentation for more information).
    """
  end

  # Dependencies can be Hex packages:
  #
  #   {:my_dep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:my_dep, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:plug, "~> 1.0"},
      {:certifi, "~> 2.3"},
      {:ex_doc, ">= 0.0.0", only: :dev},
      {:credo, "~> 0.5", only: :dev, runtime: false},
      {:dialyxir, "~> 0.5", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: :pylon_alexa_request_verifier,
      files: ["lib", "mix.exs", "README*", "LICENSE*"],
      maintainers: ["Josh Ziegler"],
      licenses: ["Apache 2.0"],
      links: %{"GitHub" => "https://github.com/pylon/alexa_request_verifier"}
    ]
  end
end
