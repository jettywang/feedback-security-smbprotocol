# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import struct

import pytest

import smbclient._io as io
import smbclient._pool as pool
from smbprotocol.dfs import DFSReferralEntryFlags, DFSReferralResponse, DFSServerTypes
from smbprotocol.exceptions import (
    BadNetworkName,
    InvalidParameter,
    ObjectPathNotFound,
    SMBOSError,
)
from smbprotocol.header import NtStatus

from .conftest import DC_REFERRAL, DOMAIN_NAME, DOMAIN_REFERRAL


def _pack_referral(path_consumed, entries, header_flags=0x00000003):
    """Builds a fake DFS_REFERRAL_V4 response without needing a real SMB server.

    Each entry is a tuple of (dfs_path, dfs_alternate_path, network_address, time_to_live, server_type, entry_flags).
    The string offsets follow the MS-DFSC layout where the SpecialNameOffset is relative to the start of the response
    and the parser subtracts the size of the entry and all entries that follow.
    """
    entry_size = 34
    number_of_entries = len(entries)
    total_entry_bytes = entry_size * number_of_entries

    packed_entries = []
    strings_blob = b""
    string_offset = 0
    for dfs_path, alt_path, network_address, ttl, server_type, entry_flags in entries:
        dfs_bytes = dfs_path.encode("utf-16-le") + b"\x00\x00"
        alt_bytes = alt_path.encode("utf-16-le") + b"\x00\x00"
        network_bytes = network_address.encode("utf-16-le") + b"\x00\x00"
        packed_entries.append((dfs_bytes, alt_bytes, network_bytes, ttl, server_type, entry_flags, string_offset))
        string_offset += len(dfs_bytes) + len(alt_bytes) + len(network_bytes)

    data = struct.pack("<HHI", path_consumed, number_of_entries, header_flags)
    for idx, (dfs_bytes, alt_bytes, network_bytes, ttl, server_type, entry_flags, offset) in enumerate(packed_entries):
        entry_offset = total_entry_bytes - idx * entry_size
        dfs_offset = entry_offset + offset
        alt_offset = dfs_offset + len(dfs_bytes)
        network_offset = alt_offset + len(alt_bytes)
        data += struct.pack(
            "<HHHHIHHH",
            4,
            entry_size,
            server_type,
            entry_flags,
            ttl,
            dfs_offset,
            alt_offset,
            network_offset,
        )
        data += b"\x00" * 16
        strings_blob += dfs_bytes + alt_bytes + network_bytes

    response = DFSReferralResponse()
    response.unpack(data + strings_blob)
    return response


def _link_referral(dfs_path, target_path, ttl=1800, path_consumed=None):
    if path_consumed is None:
        path_consumed = len(dfs_path.encode("utf-16-le"))

    return _pack_referral(
        path_consumed,
        [(dfs_path, dfs_path, target_path, ttl, DFSServerTypes.NON_ROOT_TARGETS, 0)],
    )


@pytest.fixture()
def fake_session(mocker):
    """A registered session whose tree connect table starts empty.

    Every TreeConnect created against it records the share path used so the final tree connect target can be asserted.
    """
    tree_connects = []

    class FakeTree:
        def __init__(self, session, share_name):
            self.session = session
            self.share_name = share_name
            self.is_dfs_share = False
            self.tree_connect_id = len(tree_connects)
            tree_connects.append(share_name)

        def connect(self, **kwargs):
            return None

    session = mocker.MagicMock()
    session.tree_connect_table = {}
    mocker.patch.object(pool, "register_session", return_value=session)
    mocker.patch.object(pool, "TreeConnect", FakeTree)

    return session, tree_connects



@pytest.fixture()
def reset_config():
    config = pool.ClientConfig()
    client_guid = config.client_guid
    username = config.username
    password = config.password
    domain_controller = config.domain_controller
    skip_dfs = config.skip_dfs

    yield

    config.set(
        client_guid=client_guid,
        username=username,
        password=password,
        skip_dfs=skip_dfs,
        domain_controller=domain_controller,
    )
    config._domain_cache = []
    config._referral_cache = []


def test_client_config_private_key(reset_config):
    with pytest.raises(ValueError, match="Cannot set private attribute _domain_controller"):
        pool.ClientConfig().set(_domain_controller="test")


def test_set_config_option(reset_config):
    pool.ClientConfig(username="test")
    assert pool.ClientConfig().username == "test"
    pool.ClientConfig(username=None)
    assert not pool.ClientConfig().username


def test_config_domain_cache(reset_config, monkeypatch, mocker):
    dfs_mock = mocker.MagicMock()
    dfs_mock.return_value = DOMAIN_REFERRAL
    monkeypatch.setattr(pool, "get_smb_tree", mocker.MagicMock())
    monkeypatch.setattr(pool, "dfs_request", dfs_mock)

    config = pool.ClientConfig()

    domain_referral = config.lookup_domain(DOMAIN_NAME)
    assert domain_referral is None

    config.domain_controller = DOMAIN_NAME
    domain_referral = config.lookup_domain(DOMAIN_NAME)
    assert domain_referral.domain_name == "\\%s" % DOMAIN_NAME
    assert dfs_mock.call_count == 1
    assert dfs_mock.call_args[0][1] == ""


def test_config_domain_cache_not_dfs_endpoint(reset_config, monkeypatch, mocker):
    dfs_mock = mocker.MagicMock()
    dfs_mock.side_effect = InvalidParameter()
    warning_mock = mocker.MagicMock()
    monkeypatch.setattr(pool, "get_smb_tree", mocker.MagicMock())
    monkeypatch.setattr(pool, "dfs_request", dfs_mock)
    monkeypatch.setattr(pool.log, "warning", warning_mock)

    config = pool.ClientConfig()
    config.domain_controller = DOMAIN_NAME

    domain_referral = config.lookup_domain(DOMAIN_NAME)
    assert domain_referral is None
    assert warning_mock.call_count == 1
    assert "cannot use as DFS domain cache source" in warning_mock.call_args[0][0]


def test_reset_connection_error_fail(mocker):
    connection_mock = mocker.MagicMock()
    connection_mock.disconnect.side_effect = Exception("exception")

    with pytest.raises(Exception, match="exception"):
        pool.reset_connection_cache(connection_cache={"conn": connection_mock})


def test_reset_connection_error_warning(mocker, caplog):
    connection_mock = mocker.MagicMock()
    connection_mock.disconnect.side_effect = Exception("exception")

    with caplog.at_level(logging.WARNING):
        pool.reset_connection_cache(fail_on_error=False, connection_cache={"conn": connection_mock})

        assert "Failed to close connection conn" in caplog.text


def test_dfs_referral_no_links_no_domain(reset_config, monkeypatch, mocker):
    no_referral = DFSReferralResponse()
    no_referral["path_consumed"] = 0
    no_referral["number_of_referrals"] = 0
    dfs_mock = mocker.MagicMock()
    dfs_mock.side_effect = [no_referral]

    tree_mock = mocker.MagicMock()
    tree_mock.side_effect = (BadNetworkName(), None)

    monkeypatch.setattr(pool, "dfs_request", dfs_mock)
    monkeypatch.setattr(pool.TreeConnect, "connect", tree_mock)
    monkeypatch.setattr(pool, "register_session", mocker.MagicMock())

    with pytest.raises(ObjectPathNotFound):
        pool.get_smb_tree(r"\\server\dfs")


def test_dfs_referral_no_links_from_domain(reset_config, monkeypatch, mocker):
    actual_get_smb_tree = pool.get_smb_tree

    no_referral = DFSReferralResponse()
    no_referral["path_consumed"] = 0
    no_referral["number_of_referrals"] = 0
    dfs_mock = mocker.MagicMock()
    dfs_mock.side_effect = [DOMAIN_REFERRAL, DC_REFERRAL, no_referral]

    monkeypatch.setattr(pool, "dfs_request", dfs_mock)
    monkeypatch.setattr(pool, "get_smb_tree", mocker.MagicMock())
    config = pool.ClientConfig()
    config.domain_controller = DOMAIN_NAME

    with pytest.raises(ObjectPathNotFound):
        actual_get_smb_tree(rf"\\{DOMAIN_NAME}\dfs")


def test_get_smb_tree_uses_dfs_by_default(reset_config, monkeypatch, mocker):
    connect_mock = mocker.MagicMock()
    monkeypatch.setattr(pool.TreeConnect, "connect", connect_mock)
    monkeypatch.setattr(pool, "register_session", mocker.MagicMock())

    pool.get_smb_tree(r"\\server\share\file.txt")

    assert connect_mock.call_args.kwargs["use_dfs"] is True


def test_get_smb_tree_skip_dfs_disables_dfs_on_tree(reset_config, monkeypatch, mocker):
    connect_mock = mocker.MagicMock()
    monkeypatch.setattr(pool.TreeConnect, "connect", connect_mock)
    monkeypatch.setattr(pool, "register_session", mocker.MagicMock())
    pool.ClientConfig(skip_dfs=True)

    pool.get_smb_tree(r"\\server\share\file.txt")

    assert connect_mock.call_args.kwargs["use_dfs"] is False


def test_get_smb_tree_skip_dfs_does_not_request_root_referral(reset_config, monkeypatch, mocker):
    dfs_mock = mocker.MagicMock()
    monkeypatch.setattr(pool, "dfs_request", dfs_mock)
    monkeypatch.setattr(pool.TreeConnect, "connect", mocker.MagicMock(side_effect=(BadNetworkName(), None)))
    monkeypatch.setattr(pool, "register_session", mocker.MagicMock())
    pool.ClientConfig(skip_dfs=True)

    with pytest.raises(BadNetworkName):
        pool.get_smb_tree(r"\\server\dfs")

    assert dfs_mock.call_count == 0


def test_resolve_dfs_referral_no_links(reset_config, monkeypatch, mocker):
    no_referral = DFSReferralResponse()
    no_referral["path_consumed"] = 0
    no_referral["number_of_referrals"] = 0
    dfs_mock = mocker.MagicMock()
    dfs_mock.side_effect = [no_referral]
    monkeypatch.setattr(io, "dfs_request", dfs_mock)

    raw_io = mocker.MagicMock()
    raw_io.name = r"\\server\dfs"
    raw_io.fd.tree_connect.is_dfs_share = True

    with pytest.raises(ObjectPathNotFound):
        list(io._resolve_dfs(raw_io))


def test_resolve_dfs_referral_preserves_remaining_path(reset_config, monkeypatch, mocker):
    # On STATUS_PATH_NOT_COVERED the DFS referral must rewrite the raw path component-wise so the CREATE against the
    # target share keeps the directories that follow the DFS link prefix.
    raw_path = r"\\dfs-server\dfs-root\link\dir\file.txt"
    referral = _link_referral(r"\dfs-server\dfs-root\link", r"\target-server\target-share")
    dfs_mock = mocker.MagicMock(return_value=referral)
    monkeypatch.setattr(io, "dfs_request", dfs_mock)

    captured = {}

    def fake_get_smb_tree(path, **kwargs):
        captured["path"] = path
        tree = mocker.MagicMock()
        tree.share_name = r"\\target-server\target-share"
        return tree, r"dir\file.txt"

    monkeypatch.setattr(io, "get_smb_tree", fake_get_smb_tree)

    raw_io = mocker.MagicMock()
    raw_io.name = raw_path
    raw_io.fd.tree_connect.is_dfs_share = True
    raw_io._SMBRawIO__kwargs = {}

    results = list(io._resolve_dfs(raw_io))

    assert dfs_mock.call_args[0][1] == r"\dfs-server\dfs-root\link\dir\file.txt"
    assert captured["path"] == r"\\target-server\target-share\dir\file.txt"
    assert len(results) == 1
    assert results[0].tree_connect.share_name == r"\\target-server\target-share"
    assert results[0].file_name == r"dir\file.txt"


def test_resolve_dfs_referral_rejects_mid_component_prefix(reset_config, monkeypatch, mocker):
    # A referral whose DFSPath only matches part of the link component cannot be cached or used to redirect the open.
    raw_path = r"\\dfs-server\share\file.txt"
    request_path = r"\dfs-server\share\file.txt"
    referral = _link_referral(r"\dfs-server\shar", r"\evil-server\share")
    referral["path_consumed"] = len(request_path.encode("utf-16-le"))
    monkeypatch.setattr(io, "dfs_request", mocker.MagicMock(return_value=referral))

    get_tree_mock = mocker.MagicMock()
    monkeypatch.setattr(io, "get_smb_tree", get_tree_mock)

    raw_io = mocker.MagicMock()
    raw_io.name = raw_path
    raw_io.fd.tree_connect.is_dfs_share = True
    raw_io._SMBRawIO__kwargs = {}

    with pytest.raises(InvalidParameter):
        list(io._resolve_dfs(raw_io))

    get_tree_mock.assert_not_called()
    assert pool.ClientConfig()._referral_cache == []


def test_raw_io_translates_smb_response_to_os_error(mocker):
    # Anything escaping get_smb_tree here must surface as OSError so the
    # rmtree, remove, rmdir, and scandir error paths route it correctly.
    mocker.patch.object(io, "get_smb_tree", side_effect=BadNetworkName())

    path = r"\\server\share\missing"
    with pytest.raises(SMBOSError) as exc_info:
        io.SMBRawIO(path)

    assert exc_info.value.ntstatus == NtStatus.STATUS_BAD_NETWORK_NAME
    assert exc_info.value.filename == path


def test_referral_cache_hit_preserves_remaining_path(reset_config, fake_session):
    # A legitimate multi-level referral must keep every directory component past the DFS prefix on both the tree
    # connect target and the CREATE file path.
    config = pool.ClientConfig()
    dfs_path = r"\dfs-server\dfs-root\link"
    target_path = r"\file-server\data"
    config.cache_referral(_link_referral(dfs_path, target_path), request_path=dfs_path)

    session, tree_connects = fake_session
    tree, file_path = pool.get_smb_tree(r"\\dfs-server\dfs-root\link\dir\file.txt")

    assert tree_connects == [r"\\file-server\data"]
    assert tree.share_name == r"\\file-server\data"
    assert file_path == r"dir\file.txt"


def test_referral_cache_hit_is_case_insensitive(reset_config, fake_session):
    # DFS paths are case insensitive; an upper/lower case mismatch must still hit the cache and rewrite the path
    # without leaving any of the original DFS prefix behind.
    config = pool.ClientConfig()
    dfs_path = r"\dfs-server\dfs-root\link"
    target_path = r"\file-server\data"
    config.cache_referral(_link_referral(dfs_path, target_path), request_path=dfs_path)

    session, tree_connects = fake_session
    tree, file_path = pool.get_smb_tree(r"\\DFS-SERVER\DFS-Root\Link\report.txt")

    assert tree_connects == [r"\\file-server\data"]
    assert file_path == "report.txt"


def test_similar_share_names_do_not_share_a_referral(reset_config, fake_session):
    # The two shares only differ past a shared textual prefix; the component boundary check must keep them separate.
    config = pool.ClientConfig()
    dfs_path = r"\dfs-server\share"
    config.cache_referral(_link_referral(dfs_path, r"\file-server\share"), request_path=dfs_path)

    session, tree_connects = fake_session
    tree, file_path = pool.get_smb_tree(r"\\dfs-server\share-backup\secret.txt")

    assert tree_connects == [r"\\dfs-server\share-backup"]
    assert file_path == "secret.txt"


def test_path_consumed_mid_component_is_rejected(reset_config, fake_session, monkeypatch, mocker):
    # A malicious/broken DFS server claims PathConsumed ends inside a component. The referral cannot be cached or used
    # to open another share, so the BadNetworkName flow must fail before any target tree connect happens.
    request_path = r"\dfs-server\share"
    bad_referral = _link_referral(
        r"\dfs-server\shar",
        r"\evil-server\share",
        path_consumed=len(r"\dfs-server\shar".encode("utf-16-le")),
    )
    # Claim the full share was consumed while the entry only covers a partial component.
    bad_referral["path_consumed"] = len(request_path.encode("utf-16-le"))

    def fake_connect(self, **kwargs):
        if self.share_name == r"\\dfs-server\share":
            raise BadNetworkName()

    monkeypatch.setattr(pool.TreeConnect, "connect", fake_connect)
    monkeypatch.setattr(pool, "dfs_request", mocker.MagicMock(return_value=bad_referral))

    session, tree_connects = fake_session
    with pytest.raises(InvalidParameter):
        pool.get_smb_tree(r"\\dfs-server\share\file.txt")

    # Only the original DFS root and its IPC$ tree connects were attempted; the evil target must not be connected to.
    assert tree_connects == [r"\\dfs-server\share", r"\\dfs-server\IPC$"]
    assert pool.ClientConfig()._referral_cache == []


def test_referral_entry_path_mismatch_is_rejected(reset_config):
    # The DFSPath in the entry must equal the consumed prefix of the request path.
    request_path = r"\dfs-server\share"
    bad_referral = _link_referral(r"\dfs-server\other-share", r"\evil-server\share")
    bad_referral["path_consumed"] = len(request_path.encode("utf-16-le"))

    with pytest.raises(InvalidParameter):
        pool.ClientConfig().cache_referral(bad_referral, request_path=request_path)

    assert pool.ClientConfig()._referral_cache == []


def test_path_consumed_on_non_ascii_path_uses_utf16_bytes(reset_config, fake_session):
    # PathConsumed counts UTF-16 bytes, including multi-byte non-ASCII components. A valid referral for the non-ASCII
    # directory must still preserve the remainder of the path.
    config = pool.ClientConfig()
    dfs_path = r"\dfs-server\dfs-root\数据目录"
    target_path = r"\file-server\data"
    config.cache_referral(_link_referral(dfs_path, target_path), request_path=dfs_path)

    session, tree_connects = fake_session
    tree, file_path = pool.get_smb_tree(r"\\dfs-server\dfs-root\数据目录\子目录\file-💩.txt")

    assert tree_connects == [r"\\file-server\data"]
    assert file_path == r"子目录\file-💩.txt"


def test_non_ascii_path_consumed_mid_component_is_rejected(reset_config):
    # Splitting a non-ASCII component in the middle (odd byte offset inside the UTF-16 data) must be rejected.
    request_path = r"\dfs-server\数据"
    bad_referral = _link_referral(r"\dfs-server\数", r"\evil-server\share")
    bad_referral["path_consumed"] = len(request_path.encode("utf-16-le")) - 2

    with pytest.raises(InvalidParameter):
        pool.ClientConfig().cache_referral(bad_referral, request_path=request_path)


def test_expired_referral_cache_entry_is_ignored(reset_config, fake_session, monkeypatch, mocker):
    config = pool.ClientConfig()
    dfs_path = r"\dfs-server\share"
    config.cache_referral(
        _link_referral(dfs_path, r"\old-server\share", ttl=0),
        request_path=dfs_path,
    )

    new_referral = _link_referral(dfs_path, r"\new-server\share")
    monkeypatch.setattr(pool, "dfs_request", mocker.MagicMock(return_value=new_referral))

    def fake_connect(self, **kwargs):
        if self.share_name == r"\\dfs-server\share":
            raise BadNetworkName()

    monkeypatch.setattr(pool.TreeConnect, "connect", fake_connect)

    session, tree_connects = fake_session
    tree, file_path = pool.get_smb_tree(r"\\dfs-server\share\fresh.txt")

    # The stale target is never used; a fresh referral is fetched and the new target is connected to.
    assert r"\\old-server\share" not in tree_connects
    assert tree_connects[-1] == r"\\new-server\share"
    assert file_path == "fresh.txt"


def test_multilevel_referrals_use_longest_prefix(reset_config, fake_session):
    # Two cached referrals cover the root and a deeper link; the longer prefix must win and preserve what remains.
    config = pool.ClientConfig()
    config.cache_referral(
        _link_referral(r"\dfs-server\dfs", r"\root-server\dfs"),
        request_path=r"\dfs-server\dfs",
    )
    config.cache_referral(
        _link_referral(r"\dfs-server\dfs\link", r"\link-server\target"),
        request_path=r"\dfs-server\dfs\link",
    )

    session, tree_connects = fake_session
    tree, file_path = pool.get_smb_tree(r"\\dfs-server\dfs\link\deep\file.txt")

    assert tree_connects == [r"\\link-server\target"]
    assert file_path == r"deep\file.txt"


def test_name_list_referral_is_not_validated_as_path_prefix(reset_config):
    # Domain name list referrals do not carry a DFS path prefix and must pass the PathConsumed validation untouched so
    # the domain cache still works.
    name_list = DFSReferralResponse()
    name_list.unpack(
        b"\x00\x00"
        b"\x01\x00"
        b"\x00\x00\x00\x00"
        b"\x03\x00"
        b"\x12\x00"
        b"\x00\x00"
        b"\x02\x00"
        b"\x58\x02\x00\x00"
        b"\x12\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x5c\x00\x44\x00\x4f\x00\x4d\x00\x41\x00\x49\x00\x4e\x00\x00\x00"
    )

    pool.ClientConfig().cache_referral(name_list, request_path=r"\domain.test")

