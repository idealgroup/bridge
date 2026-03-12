{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.rustc
            pkgs.cargo
            pkgs.pkg-config
            pkgs.openssl
            pkgs.bitcoind
          ];

          REGTEST_DIR = ".data/regtest";
          BITCOIN_RPC_URL = "http://127.0.0.1:18443";
          BITCOIN_RPC_USER = "idealbridge";
          BITCOIN_RPC_PASS = "idealbridge";

          shellHook = ''
            alias start-regtest='mkdir -p $REGTEST_DIR && bitcoind -regtest -datadir=$REGTEST_DIR -server -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASS -txindex -fallbackfee=0.00001 -listen=0 -daemon && echo "regtest started"'
            alias stop-regtest='bitcoin-cli -regtest -datadir=$REGTEST_DIR -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASS stop 2>/dev/null; echo "regtest stopped"'
            alias mine='bitcoin-cli -regtest -datadir=$REGTEST_DIR -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASS -generate'
          '';
        };
      });
}
