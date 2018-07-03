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
    GenServer.call(@server, {:fetch, cert_url})
  end

  @doc """
  Return either the last successfully verified root certificate,
  or nil if this is the first time the cache has been accessed.
  """
  @spec get_last_root() :: String.t() | nil
  def get_last_root do
    GenServer.call(@server, {:fetch, "root"})
  end

  @doc """
  Store a successfully verified certificate URL in the cache for next time.
  """
  @spec store(cert_url :: String.t(), cert_chain :: [String.t()]) :: :ok
  def store(cert_url, cert_chain) do
    GenServer.call(@server, {:store, cert_url, cert_chain})
  end

  @doc """
  Store a successfully verified root certificate in the cache for next time.
  """
  @spec store_root(cert :: String.t()) :: :ok
  def store_root(cert) do
    GenServer.call(@server, {:store, "root", cert})
  end

  # server process

  def start_link do
    GenServer.start_link(__MODULE__, _args = nil, name: @server)
  end

  def init(_args) do
    :ets.new(@table, [:set, :protected, :named_table])
    {:ok, _state = nil}
  end

  def handle_call({:fetch, cert_url}, _from, state) do
    data =
      case :ets.lookup(@table, cert_url) do
        [] -> nil
        [{_url, cert}] -> cert
      end

    {:reply, data, state}
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