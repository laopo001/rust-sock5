docker run -d \
    --name=ddnsto \
    -e TOKEN=a6e27f27-8b97-44ef-b2b1-747c1f85a4be \
    -e DEVICE_IDX=0 \
    -v /etc/localtime:/etc/localtime:ro \
    -e PUID=1000 \
    -e PGID=1000 \
    linkease/ddnsto