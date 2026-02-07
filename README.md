<div align="center">
<h1>mnemosyne</h1>

A process hacking library.
</div>

## Features
- hooking functions
- hooking virtual table methods
- writing and reading memory
- signature scanning

## Examples
```rs
fn main() {
  for process in process::list().unwrap() {
    if process.name == "brave" {
      println!("{}", process.id);
    }
  }
}

```
