defmodule AlexaRequestVerifier.CertCache do
  @moduledoc """
  This module caches successfully verified Amazon certificates.
  """

  use GenServer

  require Logger

  @server __MODULE__
  @table :alexa_request_verifier_certs

  # client

  @doc """
  Return either the last successfully verified Amazon certificate,
  or nil if this is the first time the cache has been accessed.
  """
  @spec get_cert(cert_url :: String.t()) :: String.t() | nil
  def get_cert(cert_url) do
    case :ets.lookup(@table, cert_url) do
      [{_url, cert}] -> cert
      [] -> nil
    end
  end

  @doc """
  Store a successfully verified certificate URL in the cache for next time.
  """
  @spec store(cert_url :: String.t(), cert_chain :: [String.t()]) :: :ok
  def store(cert_url, cert_chain) do
    GenServer.call(@server, {:store, cert_url, cert_chain})
  end

  # server process

  def start_link do
    GenServer.start_link(__MODULE__, _args = nil, name: @server)
  end

  def init(_args) do
    :ets.new(@table, [:set, :protected, :named_table])
    {:ok, _state = nil}
  end

  def handle_call({:store, cert_url, cert}, _from, state) do
    :ets.insert(@table, {cert_url, cert})
    {:reply, :ok, state}
  end

  def handle_call(:purge, _from, state) do
    :ets.delete_all_objects(@table)
    {:reply, :ok, state}
  end
end
