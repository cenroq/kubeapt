{
  description = "Flake around kubeapt";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    let
      projectName = "kubeapt";
      version = "2.1.0";
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          lib,
          system,
          ...
        }:
        let

          mkPackage =
            {
              debug ? false,
            }:
            pkgs.buildGoModule {
              src = ./.;
              name = projectName;
              inherit version;

              vendorHash = "sha256-SfgLkQ3FkAC1APryufMDXoodoRyWtzYQObuKMSqrMJ8=";

              ldflags = [
              ]
              ++ lib.optionals (!debug) [
                "-s"
                "-w"
              ];

              meta = with lib; {
                description = "Kubernetes Admission Policy Toolkit";
                homepage = "https://github.com/cenroq/kubeapt";
                license = licenses.asl20;
                mainProgram = projectName;
              };
            };

          packages = with pkgs; [
            go
          ];

          # These packages are only used as development tools - they are not required for building your packages
          devPackages = [
            pkgs.gopls
            pkgs.delve
          ];

        in
        {
          packages = {
            default = mkPackage { };
            default-debug = mkPackage { debug = true; };
          };
          devShells.default = pkgs.mkShell {
            name = "${projectName}-devshell";
            packages = packages ++ devPackages;
          };
        };
      flake = {
      };
    };
}
