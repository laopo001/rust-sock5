#!/usr/bin/env zx

cd('certificate')
await $`cargo run --verbose`
cd('..')

cd('client')
await $`cargo build --release`
cd('..')

cd('server')
await $`cargo build --release`
cd('..')