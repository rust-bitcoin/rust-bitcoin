{
  description = "rust-bitcoin workspace distributed by Nix.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Define the Rust workspace package
        rust-bitcoin = pkgs.rustPlatform.buildRustPackage {
          pname = "rust-bitcoin";
          version = "0.33.0-alpha.0";
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            pkg-config
          ];

          buildInputs = with pkgs; [
            openssl
          ];

          # Build all workspace members
          buildPhase = ''
            cargo build --release --workspace
          '';

          # Install libraries and binaries
          installPhase = ''
            mkdir -p $out/lib
            mkdir -p $out/bin

            # Copy built libraries
            find target/release -maxdepth 1 -name "*.rlib" -exec cp {} $out/lib/ \;
            find target/release -maxdepth 1 -name "*.so" -exec cp {} $out/lib/ \;
            find target/release -maxdepth 1 -name "*.dylib" -exec cp {} $out/lib/ \;
            find target/release -maxdepth 1 -name "*.a" -exec cp {} $out/lib/ \;

            # Copy all binaries (fuzz targets, examples, etc.)
            find target/release -maxdepth 1 -type f -executable -exec cp {} $out/bin/ \;

            # Copy examples if they exist
            if [ -d target/release/examples ]; then
              find target/release/examples -maxdepth 1 -type f -executable -exec cp {} $out/bin/ \;
            fi
          '';

          # Run tests during build
          doCheck = true;
          checkPhase = ''
            cargo test --workspace
          '';
        };
        # List of all binaries (fuzz targets)
        binaries = [
          "bitcoin_arbitrary_block"
          "bitcoin_arbitrary_script"
          "bitcoin_arbitrary_transaction"
          "bitcoin_arbitrary_witness"
          "bitcoin_deserialize_block"
          "bitcoin_deserialize_prefilled_transaction"
          "bitcoin_deserialize_psbt"
          "bitcoin_deserialize_script"
          "bitcoin_deserialize_transaction"
          "bitcoin_deserialize_witness"
          "bitcoin_parse_address"
          "bitcoin_parse_outpoint"
          "bitcoin_script_bytes_to_asm_fmt"
          "consensus_encoding_decode_array"
          "consensus_encoding_decode_byte_vec"
          "consensus_encoding_decode_compact_size"
          "consensus_encoding_decode_decoder2"
          "hashes_json"
          "hashes_ripemd160"
          "hashes_sha1"
          "hashes_sha256"
          "hashes_sha512"
          "hashes_sha512_256"
          "p2p_arbitrary_addrv2"
          "p2p_deserialize_addrv2"
          "p2p_deserialize_raw_net_msg"
          "units_arbitrary_weight"
          "units_parse_amount"
          "units_parse_int"
          "units_standard_checks"
        ];

        # Generate apps for each binary
        apps = builtins.listToAttrs (map (name: {
          name = name;
          value = {
            type = "app";
            program = "${rust-bitcoin}/bin/${name}";
          };
        }) binaries);
      in
      {
        packages = {
          default = rust-bitcoin;
          rust-bitcoin = rust-bitcoin;
        };

        # Export all apps
        apps = apps // {
          default = {
            type = "app";
            program = "${pkgs.writeShellScript "rust-bitcoin-help" ''
              echo "rust-bitcoin workspace - Available binaries:"
              echo ""
              ${pkgs.lib.concatMapStringsSep "\n" (name: "echo \"  nix run .#${name}\"") binaries}
              echo ""
              echo "Or use: nix run .#<binary-name>"
            ''}";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            pkg-config
            openssl
          ];

          shellHook = ''
            echo "rust-bitcoin development environment"
            echo "Available commands:"
            echo "  cargo build         - Build the workspace"
            echo "  cargo test          - Run tests"
            echo "  cargo run --example <name> - Run an example"
            echo ""
            echo "Available examples in bitcoin crate:"
            echo "  bip32, ecdsa-psbt, sign-tx-segwit-v0, sign-tx-taproot, etc."
          '';
        };
      });
}
