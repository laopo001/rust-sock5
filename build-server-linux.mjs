#!/usr/bin/env zx

await within(async () => {
    cd('server')
    await $`cargo build --release`
})

path.isAbsolute('./bin') || $`mkdir bin`

await $`cp ./target/release/server ./bin/server-linux`