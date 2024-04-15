{ pkgs ? import <nixpkgs> { } }:
let
  websocket-client = pkgs.gcc13Stdenv.mkDerivation (rec {
    name = "websocket-client";
    src = ./.;
    dontConfigure = true;
    nativeBuildInputs = [ pkgs.git ];
  });
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [     
    bintools
    llvm
    gcc13
    libgcc
  ];
}