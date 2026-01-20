set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

TARGET_TRIPLE=x86_64-unknown-linux-musl
GUEST_TEST_PATH="${SCRIPT_DIR}/../../test-binaries/target/${TARGET_TRIPLE}/release/guest_test"
RESOURCES_DIR="${SCRIPT_DIR}/resources"
PATH="/home/theo/.cargo/bin/:$PATH"

if [ -n "${GUEST_TEST_BIN:-}" ]; then
  rm -f "${RESOURCES_DIR}/guest_test"
  cp -L "${GUEST_TEST_BIN}" "${RESOURCES_DIR}/guest_test"
else
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found; install Rust or provide GUEST_TEST_BIN=path/to/guest_test"
    exit 1
  fi
  if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup not found; install rustup or provide GUEST_TEST_BIN=path/to/guest_test"
    exit 1
  fi
  if ! rustup target list --installed | grep -q "${TARGET_TRIPLE}"; then
    echo "missing ${TARGET_TRIPLE}; run: rustup target add ${TARGET_TRIPLE}"
    exit 1
  fi
  pushd "${SCRIPT_DIR}/../../test-binaries"
  cargo build --bin guest_test --target="${TARGET_TRIPLE}" --release
  popd
  rm -f "${RESOURCES_DIR}/guest_test"
  cp -L "${GUEST_TEST_PATH}" "${RESOURCES_DIR}/guest_test"
fi

IMG_ID=$(docker build -q "${SCRIPT_DIR}")
CONTAINER_ID=$(docker run -td $IMG_ID /bin/bash)

if ! sudo -n true 2>/dev/null; then
  echo "sudo requires a password; run this script in an interactive terminal or configure passwordless sudo."
  exit 1
fi


MOUNTDIR="${SCRIPT_DIR}/mnt"
FS="${SCRIPT_DIR}/rootfs.ext4"
sudo rm -r -f "${MOUNTDIR}"
sudo rm -f "${FS}"

mkdir "${MOUNTDIR}"
qemu-img create -f raw "${FS}" 800M
mkfs.ext4 "${FS}"
sudo mount "${FS}" "${MOUNTDIR}"
sudo docker cp "${CONTAINER_ID}:/" "${MOUNTDIR}"
sudo umount "${MOUNTDIR}"
rm -r "${MOUNTDIR}"
docker stop $CONTAINER_ID
docker rm $CONTAINER_ID
