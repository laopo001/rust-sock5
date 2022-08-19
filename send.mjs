await within(async () => {
    cd('server')
    await $`cargo build --release`
})

await $`cp ./target/release/server ./bin/server-linux`

await $`scp ./bin/server-linux root@38.47.100.196:/root/data/r`

// ssh -o ProxyCommand='nc -x 127.0.0.1:7891 %h %p' root@dadigua.men
