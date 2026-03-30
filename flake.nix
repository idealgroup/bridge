{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        scarb = pkgs.stdenv.mkDerivation {
          pname = "scarb";
          version = "2.16.1";
          src = pkgs.fetchurl {
            url = "https://github.com/software-mansion/scarb/releases/download/v2.16.1/scarb-v2.16.1-x86_64-unknown-linux-gnu.tar.gz";
            sha256 = "sha256-CBW0lVmrPH1AFY/ixbJ+7p+LeiiVHaU3vUj7BFo123c=";
          };
          sourceRoot = "scarb-v2.16.1-x86_64-unknown-linux-gnu";
          nativeBuildInputs = [ pkgs.autoPatchelfHook ];
          buildInputs = [ pkgs.stdenv.cc.cc.lib ];
          installPhase = ''
            mkdir -p $out/bin
            cp -r bin/* $out/bin/
          '';
        };

        universal-sierra-compiler = pkgs.stdenv.mkDerivation {
          pname = "universal-sierra-compiler";
          version = "2.7.0";
          src = pkgs.fetchurl {
            url = "https://github.com/software-mansion/universal-sierra-compiler/releases/download/v2.7.0/universal-sierra-compiler-v2.7.0-x86_64-unknown-linux-gnu.tar.gz";
            sha256 = "sha256-iPFA/HnVpHPsFVDiNqP+Ud7vt3iPBxK+iAdqFP5N4p4=";
          };
          sourceRoot = "universal-sierra-compiler-v2.7.0-x86_64-unknown-linux-gnu";
          nativeBuildInputs = [ pkgs.autoPatchelfHook ];
          buildInputs = [ pkgs.stdenv.cc.cc.lib ];
          installPhase = ''
            mkdir -p $out/bin
            cp -r bin/* $out/bin/
          '';
        };

        starknet-foundry = pkgs.stdenv.mkDerivation {
          pname = "starknet-foundry";
          version = "0.58.0";
          src = pkgs.fetchurl {
            url = "https://github.com/foundry-rs/starknet-foundry/releases/download/v0.58.0/starknet-foundry-v0.58.0-x86_64-unknown-linux-gnu.tar.gz";
            sha256 = "sha256-a1QTWjXEyK1uHuJmiNsUe+Kaaqgp8g/9FprWNslL6jw=";
          };
          sourceRoot = "starknet-foundry-v0.58.0-x86_64-unknown-linux-gnu";
          nativeBuildInputs = [ pkgs.autoPatchelfHook ];
          buildInputs = [ pkgs.stdenv.cc.cc.lib ];
          installPhase = ''
            mkdir -p $out/bin
            cp -r bin/* $out/bin/
          '';
        };

        starknet-devnet = pkgs.stdenv.mkDerivation {
          pname = "starknet-devnet";
          version = "0.7.2";
          src = pkgs.fetchurl {
            url = "https://github.com/0xSpaceShard/starknet-devnet/releases/download/v0.7.2/starknet-devnet-x86_64-unknown-linux-gnu.tar.gz";
            sha256 = "sha256-ug+UhIKzepAPDSl/3IHn7drruXyIBCldeHUcHypQvn8=";
          };
          sourceRoot = ".";
          nativeBuildInputs = [ pkgs.autoPatchelfHook ];
          buildInputs = [ pkgs.stdenv.cc.cc.lib ];
          installPhase = ''
            mkdir -p $out/bin
            cp starknet-devnet $out/bin/
          '';
        };

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.rustc
            pkgs.cargo
            pkgs.clippy
            pkgs.pkg-config
            pkgs.openssl
            pkgs.bitcoind
            scarb
            starknet-foundry
            starknet-devnet
            universal-sierra-compiler
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
