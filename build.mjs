#!/usr/bin/env zx


// console.log(argv.target) 
await within(async () => {
    cd('certificate')
    await $`cargo run --verbose`
})

let p1 = within(async () => {
    cd('client')
    await $`cargo build --release`
})


let p2 = within(async () => {
    cd('server')
    await $`cargo build --release`
})

await Promise.all([p1, p2])

await $`rm -rf bin`
await $`mkdir bin`
if (os.platform() == "windows") {
    await $`cp ./target/release/client ./bin/client-${os.platform()}.exe`
    await $`cp ./target/release/server ./bin/server-${os.platform()}.exe`
} else {
    await $`cp ./target/release/client ./bin/client-${os.platform()}`
    await $`cp ./target/release/server ./bin/server-${os.platform()}`
}