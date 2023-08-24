# How to run & verify

1. Clone this repo locally.

1. Start `Bitcoin` node via `Docker` locally:

    ```sh
    docker run -d --name=bitcoind-node -p 18444:18444 -p 18332:18332 ruimarinho/bitcoin-core -printtoconsole -regtest=1
    ```
    
1. Open shell inside root folder of the repo and start test app:

    ```sh
    cargo run
    ```
    
1. Verify the output of the app, it should be like this:

    ```
    2023-08-24T14:41:18.729623Z TRACE tokio_util::codec::framed_impl: flushing framed transport
    2023-08-24T14:41:18.729707Z TRACE tokio_util::codec::framed_impl: writing; remaining=120
    2023-08-24T14:41:18.729751Z TRACE tokio_util::codec::framed_impl: framed transport flushed
    2023-08-24T14:41:18.729768Z TRACE bitcoin_handshake: Sent version version=VersionMessage { version: 70001, services: ServiceFlags(0), timestamp: 1692888078, receiver: Address {services: ServiceFlags(NONE), address: 0.0.0.0, port: 0}, sender: Address {services: ServiceFlags(NONE), address: 0.0.0.0, port: 0}, nonce: 8980586257632375891, user_agent: "test-agent", start_height: 0, relay: false }
    2023-08-24T14:41:18.730609Z TRACE tokio_util::codec::framed_impl: attempting to decode a frame
    2023-08-24T14:41:18.730680Z TRACE tokio_util::codec::framed_impl: frame decoded from buffer
    2023-08-24T14:41:18.730695Z TRACE bitcoin_handshake: Received version their_version=VersionMessage { version: 70016, services: ServiceFlags(1033), timestamp: 1692888078, receiver: Address {services: ServiceFlags(NONE), address: 0.0.0.0, port: 0}, sender: Address {services: ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED), address: 0.0.0.0, port: 0}, nonce: 4362060617273428133, user_agent: "/Satoshi:24.0.1/", start_height: 0, relay: true }
    2023-08-24T14:41:18.730770Z TRACE tokio_util::codec::framed_impl: flushing framed transport
    2023-08-24T14:41:18.730781Z TRACE tokio_util::codec::framed_impl: writing; remaining=24
    2023-08-24T14:41:18.730818Z TRACE tokio_util::codec::framed_impl: framed transport flushed
    2023-08-24T14:41:18.797660Z TRACE bitcoin_handshake: Sent verack their_version=VersionMessage { version: 70016, services: ServiceFlags(1033), timestamp: 1692888078, receiver: Address {services: ServiceFlags(NONE), address: 0.0.0.0, port: 0}, sender: Address {services: ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED), address: 0.0.0.0, port: 0}, nonce: 4362060617273428133, user_agent: "/Satoshi:24.0.1/", start_height: 0, relay: true }
    2023-08-24T14:41:18.797685Z TRACE tokio_util::codec::framed_impl: attempting to decode a frame
    2023-08-24T14:41:18.797725Z TRACE tokio_util::codec::framed_impl: frame decoded from buffer
    2023-08-24T14:41:18.797734Z TRACE bitcoin_handshake: Received verack their_version=VersionMessage { version: 70016, services: ServiceFlags(1033), timestamp: 1692888078, receiver: Address {services: ServiceFlags(NONE), address: 0.0.0.0, port: 0}, sender: Address {services: ServiceFlags(NETWORK|WITNESS|NETWORK_LIMITED), address: 0.0.0.0, port: 0}, nonce: 4362060617273428133, user_agent: "/Satoshi:24.0.1/", start_height: 0, relay: true }
    2023-08-24T14:41:18.856786Z TRACE bitcoin_handshake: Handshake completed negotiated_version=70001
    ```
    
    Notice, that handshake is completed with negotiated version as
    `70001` (our version, due to it is smaller).
