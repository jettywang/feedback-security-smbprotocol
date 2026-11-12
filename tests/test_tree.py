# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import uuid

import pytest

from smbprotocol import Dialects
from smbprotocol.connection import Capabilities, Ciphers, Connection, SecurityMode, SigningAlgorithms
from smbprotocol.exceptions import (
    AccessDenied,
    FileClosed,
    InvalidDeviceRequest,
    NotSupported,
    SMBException,
)
from smbprotocol.header import SMB2HeaderResponse
from smbprotocol.ioctl import (
    CtlCode,
    IOCTLFlags,
    SMB2IOCTLRequest,
    SMB2IOCTLResponse,
    SMB2ValidateNegotiateInfoRequest,
    SMB2ValidateNegotiateInfoResponse,
)
from smbprotocol.session import Session
from smbprotocol.tree import (
    ShareCapabilities,
    SMB2TreeConnectRequest,
    SMB2TreeConnectResponse,
    SMB2TreeDisconnect,
    TreeConnect,
)


class TestSMB2TreeConnectRequest:
    def test_create_message(self):
        message = SMB2TreeConnectRequest()
        message["flags"] = 2
        message["buffer"] = "\\\\127.0.0.1\\c$".encode("utf-16-le")
        expected = (
            b"\x09\x00"
            b"\x02\x00"
            b"\x48\x00"
            b"\x1c\x00"
            b"\x5c\x00\x5c\x00\x31\x00\x32\x00"
            b"\x37\x00\x2e\x00\x30\x00\x2e\x00"
            b"\x30\x00\x2e\x00\x31\x00\x5c\x00"
            b"\x63\x00\x24\x00"
        )
        actual = message.pack()
        assert len(message) == 36
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeConnectRequest()
        data = (
            b"\x09\x00"
            b"\x02\x00"
            b"\x48\x00"
            b"\x1c\x00"
            b"\x5c\x00\x5c\x00\x31\x00\x32\x00"
            b"\x37\x00\x2e\x00\x30\x00\x2e\x00"
            b"\x30\x00\x2e\x00\x31\x00\x5c\x00"
            b"\x63\x00\x24\x00"
        )
        actual.unpack(data)
        assert len(actual) == 36
        assert actual["structure_size"].get_value() == 9
        assert actual["flags"].get_value() == 2
        assert actual["path_offset"].get_value() == 72
        assert actual["path_length"].get_value() == 28
        assert actual["buffer"].get_value() == "\\\\127.0.0.1\\c$".encode("utf-16-le")


class TestSMB2TreeConnectResponse:
    def test_create_message(self):
        message = SMB2TreeConnectResponse()
        message["share_type"] = 1
        message["share_flags"] = 2
        message["capabilities"] = 8
        message["maximal_access"] = 10
        expected = b"\x10\x00" b"\x01" b"\x00" b"\x02\x00\x00\x00" b"\x08\x00\x00\x00" b"\x0a\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeConnectResponse()
        data = b"\x10\x00" b"\x01" b"\x00" b"\x02\x00\x00\x00" b"\x08\x00\x00\x00" b"\x0a\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 16
        assert actual["structure_size"].get_value() == 16
        assert actual["share_type"].get_value() == 1
        assert actual["reserved"].get_value() == 0
        assert actual["share_flags"].get_value() == 2
        assert actual["capabilities"].get_value() == 8
        assert actual["maximal_access"].get_value() == 10


class TestSMB2TreeDisconnect:
    def test_create_message(self):
        message = SMB2TreeDisconnect()
        expected = b"\x04\x00" b"\x00\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = SMB2TreeDisconnect()
        data = b"\x04\x00" b"\x00\x00"
        actual.unpack(data)
        assert len(actual) == 4
        assert actual["structure_size"].get_value() == 4
        assert actual["reserved"].get_value() == 0


class TestTreeConnectUseDfs:
    def test_use_dfs(self, mocker):
        tree_response = SMB2TreeConnectResponse()
        tree_response["capabilities"] = ShareCapabilities.SMB2_SHARE_CAP_DFS

        response = SMB2HeaderResponse()
        response["tree_id"] = 10
        response["data"] = tree_response.pack()

        session = mocker.MagicMock()
        session.connection.dialect = Dialects.SMB_2_0_2
        session.connection.receive.return_value = response

        tree = TreeConnect(session, r"\\server\share")
        tree.connect(require_secure_negotiate=False)
        assert tree.is_dfs_share is True

        tree = TreeConnect(session, r"\\server\share")
        tree.connect(require_secure_negotiate=False, use_dfs=False)
        assert tree.is_dfs_share is False


class TestTreeConnectSecureNegotiateOffline:
    """Offline (no live SMB server) regressions for the FSCTL_VALIDATE_NEGOTIATE_INFO
    exchange that follows TreeConnect on the SMB 3.0 / 3.0.2 downgrade-attack check.

    The VALIDATE_NEGOTIATE_INFO response is compared against the cached NEGOTIATE
    result on 4 fields, in this order: server capabilities, server GUID, server
    security mode and server dialect. The check is skipped when:
      * require_secure_negotiate=False was requested,
      * the session is guest/anonymous (no signing key),
      * the negotiated dialect is 3.1.1+ (preauth integrity covers negotiation),
      * the server answers the IOCTL with a signed FileClosed/InvalidDeviceRequest/
        NotSupported error (an unsigned error still fails the verification).
    """

    CLIENT_GUID = uuid.UUID("11111111-1111-1111-1111-111111111111")
    SERVER_GUID = uuid.UUID("22222222-2222-2222-2222-222222222222")
    CLIENT_CAPABILITIES = (
        Capabilities.SMB2_GLOBAL_CAP_LARGE_MTU
        | Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION
        | Capabilities.SMB2_GLOBAL_CAP_DFS
    )
    SERVER_CAPABILITIES = Capabilities.SMB2_GLOBAL_CAP_LARGE_MTU | Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION
    DIALECTS = [Dialects.SMB_3_0_0, Dialects.SMB_3_0_2]
    TREE_ID = 10
    SIGNATURE = b"\xab" * 16

    @pytest.fixture
    def secure_session(self, mocker):
        connection = mocker.MagicMock()
        connection.dialect = Dialects.SMB_3_0_2
        connection.client_capabilities = self.CLIENT_CAPABILITIES
        connection.client_guid = self.CLIENT_GUID
        connection.client_security_mode = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        connection.negotiated_dialects = self.DIALECTS
        connection.server_capabilities = mocker.MagicMock()
        connection.server_capabilities.get_value.return_value = self.SERVER_CAPABILITIES
        connection.server_guid = self.SERVER_GUID
        connection.server_security_mode = SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        connection.supports_encryption = False

        session = mocker.MagicMock()
        session.username = "user"
        session.session_id = 7
        session.signing_key = b"\x01" * 16
        session.connection = connection
        session.tree_connect_table = {}
        connection.receive.return_value = self._tree_connect_response()
        return session

    def _tree_connect_response(self):
        tree_response = SMB2TreeConnectResponse()
        response = SMB2HeaderResponse()
        response["tree_id"] = self.TREE_ID
        response["data"] = tree_response.pack()
        return response

    def _validate_negotiate_response(self, **overrides):
        values = {
            "capabilities": self.SERVER_CAPABILITIES,
            "guid": self.SERVER_GUID.bytes,
            "security_mode": SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
            "dialect": Dialects.SMB_3_0_2,
        }
        values.update(overrides)

        validate = SMB2ValidateNegotiateInfoResponse()
        validate["capabilities"] = values["capabilities"]
        validate["guid"] = values["guid"]
        validate["security_mode"] = values["security_mode"]
        validate["dialect"] = values["dialect"]

        ioctl_response = SMB2IOCTLResponse()
        ioctl_response["ctl_code"] = CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        ioctl_response["file_id"] = b"\xff" * 16
        ioctl_response["output_count"] = len(validate)
        ioctl_response["buffer"] = validate.pack()

        response = SMB2HeaderResponse()
        response["tree_id"] = self.TREE_ID
        response["data"] = ioctl_response.pack()
        return response

    def _ioctl_error(self, error_type, signed):
        header = SMB2HeaderResponse()
        header["signature"] = self.SIGNATURE if signed else b"\x00" * 16
        return error_type(header)

    def _connect(self, session, receive_side_effect=None, require_secure_negotiate=True):
        connection = session.connection
        if receive_side_effect is None:
            receive_side_effect = [self._validate_negotiate_response()]
        connection.receive.side_effect = [self._tree_connect_response(), *receive_side_effect]

        tree = TreeConnect(session, r"\\server\share")
        tree.connect(require_secure_negotiate=require_secure_negotiate)
        return tree

    def _assert_ioctl_request(self, session):
        assert session.connection.send.call_count == 2
        tree_request, ioctl_request = [call.args[0] for call in session.connection.send.call_args_list]
        assert isinstance(tree_request, SMB2TreeConnectRequest)
        assert isinstance(ioctl_request, SMB2IOCTLRequest)

        # The IOCTL is sent on the unverified tree and must itself be signed.
        assert session.connection.send.call_args_list[1].kwargs == {
            "sid": session.session_id,
            "tid": self.TREE_ID,
            "force_signature": True,
        }
        assert ioctl_request["ctl_code"].get_value() == CtlCode.FSCTL_VALIDATE_NEGOTIATE_INFO
        assert ioctl_request["file_id"].get_value() == b"\xff" * 16
        assert ioctl_request["flags"].get_value() == IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL

        # Decode the embedded VALIDATE_NEGOTIATE_INFO request from the real wire bytes.
        packed = ioctl_request.pack()
        wire_request = SMB2IOCTLRequest()
        wire_request.unpack(packed)
        validate = SMB2ValidateNegotiateInfoRequest()
        validate.unpack(wire_request["buffer"].get_value())
        assert validate["capabilities"].get_value() == self.CLIENT_CAPABILITIES
        assert validate["guid"].get_value() == self.CLIENT_GUID
        assert validate["security_mode"].get_value() == SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
        assert validate["dialect_count"].get_value() == len(self.DIALECTS)
        assert validate["dialects"].get_value() == self.DIALECTS

    def test_valid_response_passes_and_registers_tree(self, secure_session):
        tree = self._connect(secure_session)

        self._assert_ioctl_request(secure_session)
        assert tree._connected is True
        assert secure_session.tree_connect_table == {self.TREE_ID: tree}

    def test_response_is_decoded_from_packed_wire_bytes(self, secure_session):
        # Repack the IOCTL response first to make sure verification works off the actual
        # SMB2 structure encoding rather than the in-memory Structure objects.
        raw = self._validate_negotiate_response().pack()
        header = SMB2HeaderResponse()
        header.unpack(raw)
        ioctl_response = SMB2IOCTLResponse()
        ioctl_response.unpack(header["data"].get_value())
        validate = SMB2ValidateNegotiateInfoResponse()
        validate.unpack(ioctl_response["buffer"].get_value())
        assert validate["dialect"].get_value() == Dialects.SMB_3_0_2
        assert validate["guid"].get_value() == self.SERVER_GUID

        tree = self._connect(secure_session, receive_side_effect=[self._validate_negotiate_response()])
        assert tree._connected is True

    @pytest.mark.parametrize(
        "field, override, expected_message",
        [
            (
                "capabilities",
                {"capabilities": Capabilities.SMB2_GLOBAL_CAP_DFS},
                "Secure negotiate failed to verify server capabilities",
            ),
            (
                "guid",
                {"guid": b"\x33" * 16},
                "Secure negotiate failed to verify server guid",
            ),
            (
                "security_mode",
                {"security_mode": SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED},
                "Secure negotiate failed to verify server security mode",
            ),
            (
                "dialect",
                {"dialect": Dialects.SMB_3_0_0},
                "Secure negotiate failed to verify server dialect, Actual: 768, Expected: 770",
            ),
        ],
        ids=["capabilities", "guid", "security-mode", "dialect"],
    )
    def test_tampered_field_fails_and_tree_is_not_usable(self, secure_session, field, override, expected_message):
        bad_response = self._validate_negotiate_response(**override)
        secure_session.connection.receive.side_effect = [self._tree_connect_response(), bad_response]
        tree = TreeConnect(secure_session, r"\\server\share")

        with pytest.raises(SMBException, match=expected_message):
            tree.connect()

        self._assert_ioctl_request(secure_session)
        # The unverified tree must not remain available for read/write operations.
        assert tree._connected is False
        assert secure_session.tree_connect_table == {}

    def test_guest_session_without_signing_key_fails(self, secure_session):
        secure_session.signing_key = None
        tree = TreeConnect(secure_session, r"\\server\share")

        with pytest.raises(SMBException, match="Cannot verify negotiate information without a session signing key"):
            tree.connect()

        # Only the TreeConnect message is sent, no IOCTL exchange is attempted.
        assert secure_session.connection.send.call_count == 1
        assert tree._connected is False
        assert secure_session.tree_connect_table == {}

    def test_smb_3_1_1_skips_ioctl_exchange(self, secure_session):
        secure_session.connection.dialect = Dialects.SMB_3_1_1

        tree = self._connect(secure_session)

        assert secure_session.connection.send.call_count == 1
        assert isinstance(secure_session.connection.send.call_args.args[0], SMB2TreeConnectRequest)
        assert secure_session.connection.receive.call_count == 1
        assert tree._connected is True
        assert secure_session.tree_connect_table == {self.TREE_ID: tree}

    def test_require_secure_negotiate_false_skips_ioctl_exchange(self, secure_session):
        tree = self._connect(secure_session, require_secure_negotiate=False)

        assert secure_session.connection.send.call_count == 1
        assert isinstance(secure_session.connection.send.call_args.args[0], SMB2TreeConnectRequest)
        assert secure_session.connection.receive.call_count == 1
        assert tree._connected is True
        assert secure_session.tree_connect_table == {self.TREE_ID: tree}

    @pytest.mark.parametrize("dialect", [Dialects.SMB_3_0_0, Dialects.SMB_3_0_2], ids=["smb-3.0.0", "smb-3.0.2"])
    @pytest.mark.parametrize(
        "error_type",
        [FileClosed, InvalidDeviceRequest, NotSupported],
        ids=["file-closed", "invalid-device-request", "not-supported"],
    )
    def test_signed_legacy_error_skips_comparison(self, secure_session, dialect, error_type):
        secure_session.connection.dialect = dialect
        error = self._ioctl_error(error_type, signed=True)

        tree = self._connect(secure_session, receive_side_effect=[error])

        self._assert_ioctl_request(secure_session)
        assert tree._connected is True
        assert secure_session.tree_connect_table == {self.TREE_ID: tree}

    @pytest.mark.parametrize(
        "error_type",
        [FileClosed, InvalidDeviceRequest, NotSupported],
        ids=["file-closed", "invalid-device-request", "not-supported"],
    )
    def test_unsigned_legacy_error_does_not_skip_comparison(self, secure_session, error_type):
        error = self._ioctl_error(error_type, signed=False)
        secure_session.connection.receive.side_effect = [self._tree_connect_response(), error]
        tree = TreeConnect(secure_session, r"\\server\share")

        with pytest.raises(error_type):
            tree.connect()

        self._assert_ioctl_request(secure_session)
        assert tree._connected is False
        assert secure_session.tree_connect_table == {}


class TestTreeConnect:
    def test_dialect_2_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_0_2)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert tree.encrypt_data is None
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_2_1_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert tree.encrypt_data is None
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_3_0_0(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_0)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert not tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_3_0_2(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert not tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_3_1_1(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_1_1)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect()
            assert not tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_dialect_2_encrypted_share(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_2_1_0)
        session = Session(connection, smb_real[0], smb_real[1], False)
        tree = TreeConnect(session, smb_real[5])
        try:
            session.connect()
            with pytest.raises(AccessDenied) as exc:
                tree.connect()
        finally:
            connection.disconnect(True)

    def test_dialect_3_encrypted_share(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_1_1)
        session = Session(connection, smb_real[0], smb_real[1])
        tree = TreeConnect(session, smb_real[5])
        try:
            session.connect()
            tree.connect()
            assert tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)

    def test_secure_negotiation_verification_failed(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        connection.dialect = Dialects.SMB_3_0_0
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            with pytest.raises(SMBException) as exc:
                tree.connect()
            assert "Secure negotiate failed to verify server dialect, Actual: 770, Expected: 768" in str(exc.value)
        finally:
            connection.disconnect(True)

    def test_secure_ignore_negotiation_verification_failed(self, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(Dialects.SMB_3_0_2)
        session = Session(connection, smb_real[0], smb_real[1])
        connection.dialect = Dialects.SMB_3_0_0
        tree = TreeConnect(session, smb_real[4])
        try:
            session.connect()
            tree.connect(False)
            assert not tree.encrypt_data
            assert not tree.is_ca_share
            assert not tree.is_dfs_share
            assert not tree.is_scaleout_share
            assert isinstance(tree.tree_connect_id, int)
        finally:
            connection.disconnect(True)
            tree.disconnect()  # test that disconnect can be run mutliple times

    @pytest.mark.parametrize(
        "cipher",
        [
            Ciphers.AES_128_CCM,
            Ciphers.AES_128_GCM,
            Ciphers.AES_256_CCM,
            Ciphers.AES_256_GCM,
        ],
        ids=["AES_128_CCM", "AES_128_GCM", "AES_256_CCM", "AES_256_GCM"],
    )
    def test_encryption(self, cipher, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(preferred_encryption_algos=[cipher])

        try:
            if connection.cipher_id == 0:
                pytest.skip("Server did not support encryption requested")

            assert connection.cipher_id == cipher

            session = Session(connection, smb_real[0], smb_real[1])
            tree = TreeConnect(session, smb_real[4])
            session.connect()
            tree.connect()

        finally:
            connection.disconnect(True)

    @pytest.mark.parametrize(
        "algo",
        [
            SigningAlgorithms.AES_GMAC,
            SigningAlgorithms.AES_CMAC,
            SigningAlgorithms.HMAC_SHA256,
        ],
        ids=["AES_GMAC", "AES_CMAC", "HMAC_SHA256"],
    )
    def test_signing(self, algo, smb_real):
        connection = Connection(uuid.uuid4(), smb_real[2], smb_real[3])
        connection.connect(preferred_signing_algos=[algo])

        try:
            if connection.signing_algorithm_id is None:
                pytest.skip("Server did not support signing algo requested")

            assert connection.signing_algorithm_id == algo

            session = Session(connection, smb_real[0], smb_real[1], require_encryption=False)
            tree = TreeConnect(session, smb_real[4])
            session.connect()
            tree.connect()

        finally:
            connection.disconnect(True)
