await within(async () => {
    cd('server')
    await $`cargo build --target=x86_64-unknown-linux-musl --release`
})

await $`cp ./target/x86_64-unknown-linux-musl/release/server ./bin/server-linux`

await  $`scp ./bin/server-linux root@silk.dadigua.men:/root/`

// ssh -o ProxyCommand='nc -x 192.168.100.142:7891 %h %p' root@dadigua.men
