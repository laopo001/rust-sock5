#!/usr/bin/env zx


// console.log(argv.target) 
// await within(async () => {
//     cd('certificate')
//     await $`cargo run --verbose`
// })

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
if (os.platform() == "win32") {
    await $`cp ./target/release/client.exe ./bin/client-windows.exe`
    await $`cp ./target/release/server.exe ./bin/server-windows.exe`
} else {
    await $`cp ./target/release/client ./bin/client-${os.platform()}`
    await $`cp ./target/release/server ./bin/server-${os.platform()}`
}