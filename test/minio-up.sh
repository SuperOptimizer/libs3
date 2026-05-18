#!/bin/sh
# Bring up a local MinIO and create the test bucket, for test_minio.
# Works with plain `docker` (no compose plugin needed).
#   sh test/minio-up.sh        # start + create bucket
#   sh test/minio-up.sh down   # stop + remove
set -e

NAME=libs3-minio
USER=libs3test
PASS=libs3secret
BUCKET=libs3-test

if [ "$1" = "down" ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "minio stopped"
    exit 0
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p 9000:9000 \
    -e MINIO_ROOT_USER="$USER" -e MINIO_ROOT_PASSWORD="$PASS" \
    minio/minio:latest server /data --address ":9000" >/dev/null

printf 'waiting for minio'
i=0
while [ $i -lt 30 ]; do
    if curl -sf http://localhost:9000/minio/health/ready >/dev/null 2>&1; then
        echo " ready"
        break
    fi
    printf '.'; sleep 1; i=$((i + 1))
done

docker run --rm --network host --entrypoint /bin/sh minio/mc:latest -c "
    mc alias set local http://localhost:9000 $USER $PASS &&
    mc mb -p local/$BUCKET" >/dev/null
echo "bucket '$BUCKET' ready -- run: LIBS3_MINIO=1 ./build/test_minio"
