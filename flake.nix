{
  description = "Caelo - free, local developer security scanner (CLI + MCP server)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    caelo-src = { url = "github:arthi-arumugam-git/caelo/bf5030b69d11fd098b1616b44fc6097296be8977"; flake = false; };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, caelo-src }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages.default = pkgs.buildNpmPackage {
          pname = "caelo";
          version = "0.1.3";

          # Immutable published release source. The lock records its content hash.
          src = pkgs.lib.cleanSourceWith {
            src = caelo-src;
            filter = file: type:
              let rel = pkgs.lib.removePrefix (toString caelo-src + "/") (toString file);
              in toString file == toString caelo-src ||
                builtins.elem rel [ "bin" "lib" "README.md" "LICENSE" "package.json" "package-lock.json" ] ||
                pkgs.lib.hasPrefix "bin/" rel || pkgs.lib.hasPrefix "lib/" rel;
          };

          # Hash of the npm dependency closure, derived from package-lock.json.
          npmDepsHash = "sha256-I1xPk25EAyUfUMt9RaMjeSDesSHchaQz3cCwj/4ks6A=";

          # Caelo is plain ESM with no compile step; skip the default `npm run build`.
          dontNpmBuild = true;

          # buildNpmPackage reads the "bin" field in package.json and installs the
          # `caelo` executable into $out/bin, patching its shebang to this nodejs.
          # Both `caelo .` (scan) and `caelo --mcp` (MCP server) then work offline.

          meta = {
            description = "Free, local developer security scanner (CLI + MCP server)";
            homepage = "https://caelo.sh";
            license = pkgs.lib.licenses.mit;
            mainProgram = "caelo";
            platforms = pkgs.lib.platforms.all;
          };
        };

        apps.default = {
          type = "app";
          meta.description = "Caelo local security scanner";
          program = "${self.packages.${system}.default}/bin/caelo";
        };
      });
}
