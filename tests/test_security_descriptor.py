# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import struct

import pytest

from smbprotocol.security_descriptor import (
    AccessAllowedAce,
    AccessDeniedAce,
    AccessMask,
    AceFlags,
    AceType,
    AclPacket,
    AclRevision,
    MalformedSecurityDescriptor,
    SDControl,
    SIDPacket,
    SMB2CreateSDBuffer,
    SystemAuditAce,
)


class TestSIDPacket:
    def test_create_message(self):
        sid = "S-1-1-0"
        message = SIDPacket()
        message.from_string(sid)
        expected = b"\x01" b"\x01" b"\x00\x00" b"\x00\x00\x00\x01" b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 12
        assert actual == expected
        assert str(message) == sid

    def test_create_domain_sid(self):
        sid = "S-1-5-21-3242954042-3778974373-1659123385-1104"
        message = SIDPacket()
        message.from_string(sid)
        expected = (
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected
        assert str(message) == sid

    def test_parse_string_fail_no_s(self):
        sid = SIDPacket()
        with pytest.raises(ValueError) as exc:
            sid.from_string("A-1-1-0")
        assert str(exc.value) == "A SID string must start with S-"

    def test_parse_string_fail_too_small(self):
        sid = SIDPacket()
        with pytest.raises(ValueError) as exc:
            sid.from_string("S-1")
        assert (
            str(exc.value) == "A SID string must start with S and contain"
            " a revision and identifier authority, e.g."
            " S-1-0"
        )

    def test_parse_message(self):
        actual = SIDPacket()
        data = b"\x01" b"\x01" b"\x00\x00" b"\x00\x00\x00\x01" b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 12
        assert str(actual) == "S-1-1-0"
        assert actual["revision"].get_value() == 1
        assert actual["sub_authority_count"].get_value() == 1
        assert actual["reserved"].get_value() == 0
        assert actual["identifier_authority"].get_value() == 1
        sub_auth = actual["sub_authorities"].get_value()
        assert isinstance(sub_auth, list)
        assert len(sub_auth) == 1
        assert sub_auth[0] == 0

    def test_parse_message_domain_sid(self):
        actual = SIDPacket()
        data = (
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 28
        assert str(actual) == "S-1-5-21-3242954042-3778974373-1659123385-1104"
        assert actual["revision"].get_value() == 1
        assert actual["sub_authority_count"].get_value() == 5
        assert actual["reserved"].get_value() == 0
        assert actual["identifier_authority"].get_value() == 5
        sub_auth = actual["sub_authorities"].get_value()
        assert isinstance(sub_auth, list)
        assert len(sub_auth) == 5
        assert sub_auth[0] == 21
        assert sub_auth[1] == 3242954042
        assert sub_auth[2] == 3778974373
        assert sub_auth[3] == 1659123385
        assert sub_auth[4] == 1104


class TestAccessAllowedAce:
    def test_create_message(self):
        sid = SIDPacket()
        sid.from_string("S-1-1-0")

        message = AccessAllowedAce()
        message["mask"] = 2032127
        message["sid"] = sid
        expected = (
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = AccessAllowedAce()
        data = (
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert actual["ace_flags"].get_value() == 0
        assert actual["ace_size"].get_value() == 20
        assert actual["mask"].get_value() == 2032127
        assert str(actual["sid"].get_value()) == "S-1-1-0"


class TestAccessDeniedAce:
    def test_create_message(self):
        sid = SIDPacket()
        sid.from_string("S-1-1-0")

        message = AccessDeniedAce()
        message["mask"] = 2032127
        message["sid"] = sid
        expected = (
            b"\x01"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = AccessDeniedAce()
        data = (
            b"\x01"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual["ace_type"].get_value() == AceType.ACCESS_DENIED_ACE_TYPE
        assert actual["ace_flags"].get_value() == 0
        assert actual["ace_size"].get_value() == 20
        assert actual["mask"].get_value() == 2032127
        assert str(actual["sid"].get_value()) == "S-1-1-0"


class TestSystemAuditAce:
    def test_create_message(self):
        sid = SIDPacket()
        sid.from_string("S-1-1-0")

        message = SystemAuditAce()
        message["mask"] = 2032127
        message["sid"] = sid
        expected = (
            b"\x02"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = SystemAuditAce()
        data = (
            b"\x02"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual["ace_type"].get_value() == AceType.SYSTEM_AUDIT_ACE_TYPE
        assert actual["ace_flags"].get_value() == 0
        assert actual["ace_size"].get_value() == 20
        assert actual["mask"].get_value() == 2032127
        assert str(actual["sid"].get_value()) == "S-1-1-0"


class TestAclPacket:
    def test_create_message(self):
        sid1 = SIDPacket()
        sid1.from_string("S-1-1-0")
        sid2 = SIDPacket()
        sid2.from_string("S-1-5-21-3242954042-3778974373-1659123385-1104")

        ace1 = AccessAllowedAce()
        ace1["mask"] = 2032127
        ace1["sid"] = sid1
        ace2 = AccessAllowedAce()
        ace2["mask"] = 2032127
        ace2["sid"] = sid2
        # define an illegal ACE for tests to see if it is flexible for custom
        # aces'
        ace3 = AccessAllowedAce()
        ace3["ace_type"] = AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
        ace3["sid"] = sid1

        message = AclPacket()
        message["aces"] = [ace1, ace2, ace3.pack()]
        expected = (
            b"\x02"
            b"\x00"
            b"\x54\x00"
            b"\x03\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x24\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x05"
            b"\x00"
            b"\x14\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 84
        assert actual == expected

    def test_parse_message(self):
        actual = AclPacket()
        data = (
            b"\x02"
            b"\x00"
            b"\x54\x00"
            b"\x03\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x24\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x05"
            b"\x00"
            b"\x14\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )

        actual.unpack(data)
        assert len(actual) == 84
        assert actual["acl_revision"].get_value() == AclRevision.ACL_REVISION
        assert actual["sbz1"].get_value() == 0
        assert actual["acl_size"].get_value() == 84
        assert actual["ace_count"].get_value() == 3
        assert actual["sbz2"].get_value() == 0
        aces = actual["aces"].get_value()
        assert len(aces) == 3

        assert aces[0]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert aces[0]["ace_flags"].get_value() == 0
        assert aces[0]["ace_size"].get_value() == 20
        assert aces[0]["mask"].get_value() == 2032127
        assert str(aces[0]["sid"].get_value()) == "S-1-1-0"

        assert aces[1]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert aces[1]["ace_flags"].get_value() == 0
        assert aces[1]["ace_size"].get_value() == 36
        assert aces[1]["mask"].get_value() == 2032127
        assert str(aces[1]["sid"].get_value()) == "S-1-5-21-3242954042-3778974373-1659123385-1104"

        assert isinstance(aces[2], bytes)
        assert aces[2] == b"\x05\x00\x14\x00\x00\x00\x00\x00" b"\x01\x01\x00\x00\x00\x00\x00\x01" b"\x00\x00\x00\x00"


class TestSMB2SDBuffer:
    def test_create_message(self):
        sid1 = SIDPacket()
        sid1.from_string("S-1-1-0")
        sid2 = SIDPacket()
        sid2.from_string("S-1-5-21-3242954042-3778974373-1659123385-1104")

        ace1 = AccessAllowedAce()
        ace1["mask"] = 2032127
        ace1["sid"] = sid1
        ace2 = AccessAllowedAce()
        ace2["mask"] = 2032127
        ace2["sid"] = sid2
        acl = AclPacket()
        acl["aces"] = [ace1, ace2]

        message = SMB2CreateSDBuffer()
        message["control"].set_flag(SDControl.SELF_RELATIVE)
        message.set_dacl(acl)
        message.set_owner(sid2)
        message.set_group(sid1)
        message.set_sacl(None)

        expected = (
            b"\x01"
            b"\x00"
            b"\x04\x80"
            b"\x54\x00\x00\x00"
            b"\x70\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00"
            b"\x02"
            b"\x00"
            b"\x40\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x24\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x01\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 124
        assert actual == expected

    def test_create_message_sacl_group(self):
        sid = SIDPacket()
        sid.from_string("S-1-1-0")

        ace = AccessAllowedAce()
        ace["sid"] = sid
        acl = AclPacket()
        acl["aces"] = [ace]

        message = SMB2CreateSDBuffer()
        message.set_dacl(None)
        message.set_owner(None)
        message.set_group(sid)
        message.set_sacl(acl)

        expected = (
            b"\x01"
            b"\x00"
            b"\x10\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x02"
            b"\x00"
            b"\x1c\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 60
        assert actual == expected

    def test_parse_message_sacl_group(self):
        actual = SMB2CreateSDBuffer()
        data = (
            b"\x01"
            b"\x00"
            b"\x10\x80"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00"
            b"\x20\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x02"
            b"\x00"
            b"\x1c\x00"
            b"\x01\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 60
        assert actual["revision"].get_value() == 1
        assert actual["sbz1"].get_value() == 0
        assert actual["control"].get_value() == 0x8010
        assert actual["offset_owner"].get_value() == 0
        assert actual["offset_group"].get_value() == 20
        assert actual["offset_sacl"].get_value() == 32
        assert actual["offset_dacl"].get_value() == 0
        assert len(actual["buffer"]) == 40

        assert not actual.get_owner()
        assert str(actual.get_group()) == "S-1-1-0"
        sacl = actual.get_sacl()
        assert sacl["acl_revision"].get_value() == AclRevision.ACL_REVISION
        assert sacl["sbz1"].get_value() == 0
        assert sacl["acl_size"].get_value() == 28
        assert sacl["ace_count"].get_value() == 1
        assert sacl["sbz2"].get_value() == 0
        saces = sacl["aces"].get_value()
        assert isinstance(saces, list)
        assert len(saces) == 1
        assert saces[0]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert saces[0]["ace_flags"].get_value() == 0
        assert saces[0]["ace_size"].get_value() == 20
        assert saces[0]["mask"].get_value() == 0
        assert str(saces[0]["sid"]) == "S-1-1-0"

        assert not actual.get_dacl()

    def test_parse_message(self):
        actual = SMB2CreateSDBuffer()
        data = (
            b"\x01"
            b"\x00"
            b"\x04\x80"
            b"\x54\x00\x00\x00"
            b"\x70\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x14\x00\x00\x00"
            b"\x02"
            b"\x00"
            b"\x40\x00"
            b"\x02\x00"
            b"\x00\x00"
            b"\x00"
            b"\x00"
            b"\x14\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x24\x00"
            b"\xff\x01\x1f\x00"
            b"\x01"
            b"\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x01\x05"
            b"\x00\x00"
            b"\x00\x00\x00\x05"
            b"\x15\x00\x00\x00"
            b"\x3a\x8d\x4b\xc1"
            b"\xa5\x92\x3e\xe1"
            b"\xb9\x36\xe4\x62"
            b"\x50\x04\x00\x00"
            b"\x01"
            b"\x01"
            b"\x00\x00"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x00"
        )
        actual.unpack(data)
        assert len(actual) == 124
        assert actual["revision"].get_value() == 1
        assert actual["sbz1"].get_value() == 0
        assert actual["control"].get_value() == 32772
        assert actual["offset_owner"].get_value() == 84
        assert actual["offset_group"].get_value() == 112
        assert actual["offset_sacl"].get_value() == 0
        assert actual["offset_dacl"].get_value() == 20
        assert len(actual["buffer"]) == 104

        assert str(actual.get_owner()) == "S-1-5-21-3242954042-3778974373-1659123385-1104"
        assert str(actual.get_group()) == "S-1-1-0"
        assert not actual.get_sacl()
        dacl = actual.get_dacl()
        assert dacl["acl_revision"].get_value() == AclRevision.ACL_REVISION
        assert dacl["sbz1"].get_value() == 0
        assert dacl["acl_size"].get_value() == 64
        assert dacl["ace_count"].get_value() == 2
        assert dacl["sbz2"].get_value() == 0
        daces = dacl["aces"].get_value()
        assert isinstance(daces, list)
        assert len(daces) == 2
        assert daces[0]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert daces[0]["ace_flags"].get_value() == 0
        assert daces[0]["ace_size"].get_value() == 20
        assert daces[0]["mask"].get_value() == 2032127
        assert str(daces[0]["sid"]) == "S-1-1-0"
        assert daces[1]["ace_type"].get_value() == AceType.ACCESS_ALLOWED_ACE_TYPE
        assert daces[1]["ace_flags"].get_value() == 0
        assert daces[1]["ace_size"].get_value() == 36
        assert daces[1]["mask"].get_value() == 2032127
        assert str(daces[1]["sid"]) == "S-1-5-21-3242954042-3778974373-1659123385-1104"

    def test_parse_acl_rejects_data_not_covered_by_ace_count(self):
        # The ACL declares 3 ACEs but AclSize covers extra trailing bytes that
        # no ACE accounts for. Rewriting such an ACL would silently drop the
        # trailing data, so the descriptor must be rejected instead.
        actual = AclPacket()
        data = (
            b"\x02"
            b"\x00"
            b"\x93\x00"
            b"\x03\x00"
            b"\x00\x00"
            b"\x00\x00\x14\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
            b"\x00\x00\x14\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0c\x00\x00\x00"
            b"\x00\x00\x14\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x07\x00\x00\x00"
            b"exceeding data after ACEs after ace_count which should be ignored while parsing"
        )
        with pytest.raises(MalformedSecurityDescriptor, match="trailing byte"):
            actual.unpack(data)


def _sid(sid_string):
    sid_packet = SIDPacket()
    sid_packet.from_string(sid_string)
    return sid_packet


def _sd_header(control, owner=0, group=0, sacl=0, dacl=0):
    return struct.pack("<BBHIIII", 1, 0, control, owner, group, sacl, dacl)


def _ace(ace_type=AceType.ACCESS_ALLOWED_ACE_TYPE, mask=2032127, flags=0, sid_string="S-1-1-0"):
    ace_packet = AccessAllowedAce()
    ace_packet["ace_type"] = ace_type
    ace_packet["mask"] = mask
    ace_packet["ace_flags"] = flags
    ace_packet["sid"] = _sid(sid_string)
    return ace_packet


def _acl(aces):
    acl_packet = AclPacket()
    acl_packet["aces"] = aces
    return acl_packet


class TestAclPacketStrictParsing:
    def test_unknown_ace_is_preserved_verbatim(self):
        # AceType 0x13 (SYSTEM_SCOPED_POLICY_ID_ACE_TYPE) has no dedicated
        # structure and must survive a parse/pack cycle byte-for-byte.
        unknown_ace = (
            b"\x13"
            b"\x40"
            b"\x18\x00"
            b"\x01\x02\x03\x04"
            + _sid("S-1-1-0").pack()
            + b"\x00\x00\x00\x00"
        )
        acl_packet = _acl([unknown_ace])
        raw = acl_packet.pack()

        parsed = AclPacket()
        parsed.unpack(raw)
        assert parsed["aces"].get_value() == [unknown_ace]
        assert parsed.pack() == raw

    def test_ace_size_zero_is_rejected(self):
        data = struct.pack("<BBHHH", 2, 0, 16, 1, 0) + b"\x00\x00\x00\x00" + b"X" * 4
        with pytest.raises(MalformedSecurityDescriptor, match="AceSize of 0"):
            AclPacket().unpack(data)

    def test_ace_size_overrun_is_rejected(self):
        data = struct.pack("<BBHHH", 2, 0, 16, 1, 0) + b"\x00\x00\x20\x00" + b"X" * 4
        with pytest.raises(MalformedSecurityDescriptor, match="exceeds"):
            AclPacket().unpack(data)

    def test_ace_count_mismatch_is_rejected(self):
        good_ace = _ace().pack()
        data = struct.pack("<BBHHH", 2, 0, 8 + len(good_ace), 2, 0) + good_ace
        with pytest.raises(MalformedSecurityDescriptor, match="AceCount 2"):
            AclPacket().unpack(data)

    def test_acl_size_smaller_than_header_is_rejected(self):
        with pytest.raises(MalformedSecurityDescriptor, match="AclSize"):
            AclPacket().unpack(struct.pack("<BBHHH", 2, 0, 4, 0, 0))

    def test_acl_size_larger_than_data_is_rejected(self):
        data = struct.pack("<BBHHH", 2, 0, 200, 0, 0)
        with pytest.raises(MalformedSecurityDescriptor, match="AclSize 200"):
            AclPacket().unpack(data)

    def test_known_ace_size_mismatch_is_rejected(self):
        # Declare the ACE shorter than the known ACE structure parses to.
        good_ace = bytearray(_ace().pack())
        good_ace[2:4] = struct.pack("<H", 16)
        raw_acl = struct.pack("<BBHHH", 2, 0, len(good_ace) + 8, 1, 0) + bytes(good_ace)
        with pytest.raises(MalformedSecurityDescriptor, match="could not be parsed"):
            AclPacket().unpack(raw_acl)

    def test_zero_ace_dacl_roundtrips(self):
        raw_acl = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
        acl_packet = AclPacket()
        acl_packet.unpack(raw_acl)
        assert acl_packet["ace_count"].get_value() == 0
        assert acl_packet["aces"].get_value() == []
        assert acl_packet.pack() == raw_acl


class TestSecurityDescriptorDaclStates:
    def test_absent_dacl(self):
        raw = _sd_header(SDControl.SELF_RELATIVE)
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)

        assert sd.is_dacl_present() is False
        assert sd.is_dacl_null() is False
        assert sd.get_dacl() is None
        assert sd.pack() == raw

    def test_null_dacl(self):
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT)
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)

        assert sd.is_dacl_present() is True
        assert sd.is_dacl_null() is True
        assert sd.get_dacl() is None
        assert sd.pack() == raw

    def test_build_null_dacl(self):
        sd = SMB2CreateSDBuffer()
        sd["control"].set_flag(SDControl.SELF_RELATIVE)
        sd.set_null_dacl()

        assert sd.is_dacl_present() is True
        assert sd.is_dacl_null() is True
        assert sd["offset_dacl"].get_value() == 0
        assert sd.pack() == _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT)

    def test_set_dacl_none_removes_instead_of_null(self):
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT)
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)
        sd.set_dacl(None)

        assert sd.is_dacl_present() is False
        assert sd.is_dacl_null() is False

    def test_zero_ace_dacl_is_distinct_from_null(self):
        empty_dacl = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT, dacl=20) + empty_dacl
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)

        assert sd.is_dacl_present() is True
        assert sd.is_dacl_null() is False
        dacl = sd.get_dacl()
        assert dacl is not None
        assert dacl["ace_count"].get_value() == 0
        assert sd.pack() == raw

    def test_absent_and_null_sacl_distinction(self):
        absent = SMB2CreateSDBuffer()
        absent.unpack(_sd_header(SDControl.SELF_RELATIVE))
        assert absent.is_sacl_present() is False
        assert absent.is_sacl_null() is False

        null_raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.SACL_PRESENT)
        null_sd = SMB2CreateSDBuffer()
        null_sd.unpack(null_raw)
        assert null_sd.is_sacl_present() is True
        assert null_sd.is_sacl_null() is True
        assert null_sd.get_sacl() is None
        assert null_sd.pack() == null_raw

    def test_null_owner_roundtrips(self):
        # SELF_RELATIVE with a DACL but a NULL owner (offset_owner == 0).
        empty_dacl = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT, dacl=20) + empty_dacl
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)

        assert sd.get_owner() is None
        assert sd.get_dacl() is not None
        assert sd.pack() == raw


class TestSecurityDescriptorReadModifyWrite:
    def _full_descriptor(self):
        owner = _sid("S-1-5-32")
        group = _sid("S-1-5-18")
        inherited_ace = _ace(mask=0x1F01FF, flags=AceFlags.INHERITED_ACE | AceFlags.OBJECT_INHERIT_ACE)
        explicit_ace = _ace(mask=0x120089, flags=AceFlags.CONTAINER_INHERIT_ACE)
        unknown_ace = b"\x11\x00\x14\x00" + b"\x00" * 4 + _sid("S-1-16-12288").pack()
        dacl = _acl([inherited_ace, explicit_ace, unknown_ace])
        sacl = _acl([_ace(ace_type=AceType.SYSTEM_AUDIT_ACE_TYPE, mask=AccessMask.SYNCHRONIZE)])

        dacl_bytes, sacl_bytes = dacl.pack(), sacl.pack()
        owner_bytes, group_bytes = owner.pack(), group.pack()
        dacl_offset = 20
        sacl_offset = dacl_offset + len(dacl_bytes)
        owner_offset = sacl_offset + len(sacl_bytes)
        group_offset = owner_offset + len(owner_bytes)
        control = (
            SDControl.SELF_RELATIVE
            | SDControl.DACL_PRESENT
            | SDControl.SACL_PRESENT
            | SDControl.DACL_PROTECTED
        )
        raw = (
            _sd_header(control, owner_offset, group_offset, sacl_offset, dacl_offset)
            + dacl_bytes
            + sacl_bytes
            + owner_bytes
            + group_bytes
        )
        return raw, unknown_ace

    def test_noop_roundtrip_is_byte_identical(self):
        raw, _ = self._full_descriptor()
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)
        assert sd.pack() == raw

    def test_modifying_one_ace_preserves_everything_else(self):
        raw, unknown_ace = self._full_descriptor()
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)

        dacl = sd.get_dacl()
        aces = dacl["aces"].get_value()
        new_mask = 0xDEADBEEF
        aces[0]["mask"] = new_mask
        dacl["aces"] = aces
        sd.set_dacl(dacl)

        # The ACE mask lives at SD header (20) + ACL header (8) + ACE header (4).
        mask_offset = 20 + 8 + 4
        expected = raw[:mask_offset] + struct.pack("<I", new_mask) + raw[mask_offset + 4 :]
        assert sd.pack() == expected

        rewritten = SMB2CreateSDBuffer()
        rewritten.unpack(sd.pack())
        rewritten_aces = rewritten.get_dacl()["aces"].get_value()
        assert rewritten_aces[0]["ace_flags"].get_value() == (
            AceFlags.INHERITED_ACE | AceFlags.OBJECT_INHERIT_ACE
        )
        assert rewritten_aces[0]["mask"].get_value() == new_mask
        assert rewritten_aces[1]["ace_flags"].get_value() == AceFlags.CONTAINER_INHERIT_ACE
        assert rewritten_aces[2] == unknown_ace
        assert str(rewritten.get_owner()) == "S-1-5-32"
        assert str(rewritten.get_group()) == "S-1-5-18"
        assert rewritten["control"].has_flag(SDControl.SACL_PRESENT)
        assert rewritten["control"].has_flag(SDControl.DACL_PROTECTED)

    def test_modifying_dacl_keeps_owner_group_sacl_bytes(self):
        raw, _ = self._full_descriptor()
        original = SMB2CreateSDBuffer()
        original.unpack(raw)
        original_owner = original.get_owner().pack()
        original_group = original.get_group().pack()
        original_sacl = original.get_sacl().pack()

        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)
        dacl = sd.get_dacl()
        aces = dacl["aces"].get_value()
        aces[0]["mask"] = 0x00000001
        dacl["aces"] = aces
        sd.set_dacl(dacl)

        rewritten = SMB2CreateSDBuffer()
        rewritten.unpack(sd.pack())
        assert rewritten.get_owner().pack() == original_owner
        assert rewritten.get_group().pack() == original_group
        assert rewritten.get_sacl().pack() == original_sacl


class TestSecurityDescriptorMalformedRejection:
    def test_dacl_offset_beyond_buffer(self):
        empty_dacl = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT, dacl=200) + empty_dacl
        with pytest.raises(MalformedSecurityDescriptor, match="outside"):
            SMB2CreateSDBuffer().unpack(raw)

    def test_dacl_offset_inside_header(self):
        empty_dacl = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT, dacl=4) + empty_dacl
        with pytest.raises(MalformedSecurityDescriptor, match="header"):
            SMB2CreateSDBuffer().unpack(raw)

    def test_present_flag_clear_with_non_zero_offset(self):
        empty_dacl = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
        raw = _sd_header(SDControl.SELF_RELATIVE, dacl=20) + empty_dacl
        with pytest.raises(MalformedSecurityDescriptor, match="absent"):
            SMB2CreateSDBuffer().unpack(raw)

    def test_acl_size_extends_beyond_buffer(self):
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT, dacl=20)
        raw += struct.pack("<BBHHH", 2, 0, 200, 0, 0)
        with pytest.raises(MalformedSecurityDescriptor, match="extends beyond"):
            SMB2CreateSDBuffer().unpack(raw)

    def test_truncated_acl_header(self):
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT, dacl=20) + b"\x02\x00\x08"
        with pytest.raises(MalformedSecurityDescriptor, match="ACL header"):
            SMB2CreateSDBuffer().unpack(raw)

    def test_truncated_sid(self):
        raw = _sd_header(SDControl.SELF_RELATIVE, owner=20)
        raw += b"\x01\x05\x00\x00\x00\x00\x00\x05\x00\x00\x00\x15"
        with pytest.raises(MalformedSecurityDescriptor, match="sub-authorities"):
            SMB2CreateSDBuffer().unpack(raw)

    def test_absolute_descriptor_with_buffer_is_rejected(self):
        empty_dacl = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
        raw = _sd_header(SDControl.DACL_PRESENT, dacl=20) + empty_dacl
        with pytest.raises(MalformedSecurityDescriptor, match="self-relative"):
            SMB2CreateSDBuffer().unpack(raw)

    def test_overlapping_components_are_rejected(self):
        sid_bytes = _sid("S-1-1-0").pack()
        raw = _sd_header(SDControl.SELF_RELATIVE, owner=20, group=24) + sid_bytes + sid_bytes
        with pytest.raises(MalformedSecurityDescriptor, match="overlap"):
            SMB2CreateSDBuffer().unpack(raw)

    def test_ace_size_zero_inside_descriptor_is_rejected(self):
        bad_acl = struct.pack("<BBHHH", 2, 0, 16, 1, 0) + b"\x00\x00\x00\x00" + b"X" * 4
        raw = _sd_header(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT, dacl=20) + bad_acl
        with pytest.raises(MalformedSecurityDescriptor, match="AceSize of 0"):
            SMB2CreateSDBuffer().unpack(raw)


class TestSecurityDescriptorOnWire:
    def test_query_info_response_carries_descriptor_unchanged(self):
        from smbprotocol.open import SMB2QueryInfoResponse

        raw, _ = TestSecurityDescriptorReadModifyWrite()._full_descriptor()
        response = SMB2QueryInfoResponse()
        response["buffer"] = raw
        packed = response.pack()

        parsed_response = SMB2QueryInfoResponse()
        parsed_response.unpack(packed)
        assert parsed_response["output_buffer_length"].get_value() == len(raw)

        parsed_sd = SMB2CreateSDBuffer()
        parsed_sd.unpack(parsed_response["buffer"].get_value())
        assert parsed_sd.pack() == raw

    def test_set_info_request_carries_rewritten_descriptor(self):
        from smbprotocol.open import InfoAdditionalInformation, SMB2SetInfoRequest

        raw, _ = TestSecurityDescriptorReadModifyWrite()._full_descriptor()
        sd = SMB2CreateSDBuffer()
        sd.unpack(raw)
        dacl = sd.get_dacl()
        aces = dacl["aces"].get_value()
        aces[0]["mask"] = 0x00000005
        dacl["aces"] = aces
        sd.set_dacl(dacl)
        descriptor_bytes = sd.pack()

        request = SMB2SetInfoRequest()
        request["additional_information"].set_flag(InfoAdditionalInformation.DACL_SECURITY_INFORMATION)
        request["file_id"] = b"\xff" * 16
        request["buffer"] = descriptor_bytes
        packed = request.pack()

        parsed_request = SMB2SetInfoRequest()
        parsed_request.unpack(packed)
        assert parsed_request["buffer_length"].get_value() == len(descriptor_bytes)
        assert parsed_request["buffer"].get_value() == descriptor_bytes
        assert parsed_request["additional_information"].has_flag(
            InfoAdditionalInformation.DACL_SECURITY_INFORMATION
        )

        roundtripped = SMB2CreateSDBuffer()
        roundtripped.unpack(parsed_request["buffer"].get_value())
        assert roundtripped.get_dacl()["aces"].get_value()[0]["mask"].get_value() == 5
