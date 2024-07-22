# `pngme`
CLI tool to hide secret messages in PNG files, based on https://jrdngr.github.io/pngme_book/. 

### demo
[![asciicast](https://asciinema.ilmul.com/a/Qkv5CuXSsb78XUMYvfVYdUiLm.svg)](https://asciinema.ilmul.com/a/Qkv5CuXSsb78XUMYvfVYdUiLm)

### building

Ensure you have [`Zig (version 0.13.0)`](https://ziglang.org/learn/getting-started/#installing-zig).

``` console
$ zig build -Doptimize=ReleaseFast
```

The executable will be compiled as `./zig-out/bin/pngme`.
