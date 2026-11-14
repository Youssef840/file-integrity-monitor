import hashlib

import pytest

from fim.hasher import CHUNK_SIZE, hash_bytes, hash_file, validate_algorithm


def test_sha256_known_vector(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_bytes(b"hello")
    assert hash_file(f) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_large_file_is_hashed_in_chunks(tmp_path):
    data = b"x" * (CHUNK_SIZE * 3 + 17)
    f = tmp_path / "big.bin"
    f.write_bytes(data)
    assert hash_file(f) == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("algo", ["sha512", "sha3_256", "blake2b", "md5", "sha1"])
def test_other_algorithms(tmp_path, algo):
    f = tmp_path / "a"
    f.write_bytes(b"abc")
    assert hash_file(f, algo) == hashlib.new(algo, b"abc").hexdigest()
    assert hash_bytes(b"abc", algo) == hashlib.new(algo, b"abc").hexdigest()


def test_missing_file_and_directory_return_none(tmp_path):
    assert hash_file(tmp_path / "nope") is None
    assert hash_file(tmp_path) is None


def test_algorithm_validation():
    assert validate_algorithm("SHA-256") == "sha256"
    assert validate_algorithm("sha3-256") == "sha3_256"
    with pytest.raises(ValueError):
        validate_algorithm("crc32")
