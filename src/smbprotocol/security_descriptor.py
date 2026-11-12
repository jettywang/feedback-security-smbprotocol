# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import struct
from collections import OrderedDict

from smbprotocol.structure import (
    BytesField,
    EnumField,
    FlagField,
    IntField,
    ListField,
    Structure,
    StructureField,
)


class MalformedSecurityDescriptor(Exception):
    """Raised when a self-relative security descriptor cannot be parsed or safely rewritten.

    A read-modify-write operation must never silently drop parts of a security descriptor (owner,
    group, SACL/DACL, individual ACEs or padding). When the on-wire structure is malformed in a way
    that makes a lossless round-trip impossible the descriptor is rejected instead of being
    rewritten so the caller can fail closed.
    """


# Size, in bytes, of the self-relative SECURITY_DESCRIPTOR header that precedes the buffer.
SD_HEADER_SIZE = 20

# Minimum size of an ACL header ([MS-DTYP] 2.4.5 ACL) and an individual ACE header.
ACL_HEADER_SIZE = 8
ACE_HEADER_SIZE = 4


class AccessMask:
    """
    [MS-DTYP]

    2.4.3 ACCESS_MASK
    32-bit set of flags that are used to encode the user rights to an object.
    This is just a generic setup of access mask flags to set an can vary
    from the object being set. When setting the AccessMask on an ACE packet,
    any 32-bit value can be used and this is just as a guideline.
    """

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    SYNCHRONIZE = 0x00100000
    WRITE_OWNER = 0x00080000
    WRITE_DACL = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000


class AceType:
    """
    [MS-DTYP]

    2.4.4.1 ACE_HEADER AceType
    The type of ACE in the ACE packet.
    """

    # Current only have structures for the first 3
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01
    SYSTEM_AUDIT_ACE_TYPE = 0x02

    # No structures are defined for the below
    SYSTEM_ALARM_ACE_TYPE = 0x03
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13


class AceFlags:
    """
    [MS-DTYP]

    2.4.4.1 ACE_HEADER AceFlags
    Controls the ACE specified in the ACE packet.
    """

    CONTAINER_INHERIT_ACE = 0x02
    FAILED_ACCESS_ACE_FLAG = 0x80
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10
    NO_PROPAGATE_INHERITY_ACE = 0x04
    OBJECT_INHERIT_ACE = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40


class AclRevision:
    """
    [MS-DTYP]

    2.4.5 ACL AclRevision
    ACL_REVISION - AceType 0, 1, 2, 3, 11, 12, 13 are valid
    ACL_REVISION_DS - AceType 5, 6, 7, 8, 11 are valid (Directory Service)
    """

    ACL_REVISION = 0x02
    ACL_REVISION_DS = 0x04  # not natively supported yet


class SDControl:
    """
    [MS-DTYP]

    2.4.6 SECURITY_DESCRIPTOR Control
    Specifies control access bit flags.
    """

    SELF_RELATIVE = 0x8000
    RM_CONTROL_VALID = 0x4000
    SACL_PROTECTED = 0x2000
    DACL_PROTECTED = 0x1000
    SACL_AUTO_INHERITED = 0x0800
    DACL_AUTO_INHERITED = 0x0400
    SACL_COMPUTED_INHERITANCE_REQUIRED = 0x0200
    DACL_COMPUTED_INHERITANCE_REQUIRED = 0x0100
    SERVER_SECURITY = 0x0080
    DACL_TRUSTED = 0x0040
    SACL_DEFAULTED = 0x0020
    SACL_PRESENT = 0x0010
    DACL_DEFAULTED = 0x0008
    DACL_PRESENT = 0x0004
    GROUP_DEFAULTED = 0x0002
    OWNER_DEFAULTED = 0x0001
    NONE = 0x0000


class SIDPacket(Structure):
    """
    [MS-DTYP] 2.4.2.2 SID--Packet Representation

    The packet representation of the SID type for use by block protocols. While
    the values can be set explicitly, it may be easier to use the from_string
    function store the byte structure from the string format.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("revision", IntField(size=1, default=1)),
                ("sub_authority_count", IntField(size=1, default=lambda s: len(s["sub_authorities"].get_value()))),
                ("reserved", IntField(size=2)),
                ("identifier_authority", IntField(size=4, little_endian=False)),
                (
                    "sub_authorities",
                    ListField(list_type=IntField(size=4), list_count=lambda s: s["sub_authority_count"].get_value()),
                ),
            ]
        )
        super().__init__()

    def __str__(self):
        revision = self["revision"].get_value()
        id_authority = self["identifier_authority"].get_value()
        sub_authorities = self["sub_authorities"].get_value()
        authorities_string = "-".join(str(x) for x in sub_authorities)
        sid_string = f"S-{revision}-{id_authority}-{authorities_string}"
        return sid_string

    def from_string(self, sid_string):
        """
        Used to set the structure parameters based on the input string

        :param sid_string: String of the sid in S-x-x-x-x form
        """
        if not sid_string.startswith("S-"):
            raise ValueError("A SID string must start with S-")

        sid_entries = sid_string.split("-")
        if len(sid_entries) < 3:
            raise ValueError(
                "A SID string must start with S and contain a revision and identifier authority, e.g. S-1-0"
            )

        revision = int(sid_entries[1])
        id_authority = int(sid_entries[2])
        sub_authorities = [int(i) for i in sid_entries[3:]]

        self["revision"].set_value(revision)
        self["identifier_authority"].set_value(id_authority)
        self["sub_authorities"] = sub_authorities


class AccessAllowedAce(Structure):
    """
    [MS-DTYP] 2.4.4.3 ACCESS_ALLOWED_ACE

    Used for the DACL that controls access to an object.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("ace_type", EnumField(size=1, default=AceType.ACCESS_ALLOWED_ACE_TYPE, enum_type=AceType)),
                ("ace_flags", FlagField(size=1, flag_type=AceFlags)),
                ("ace_size", IntField(size=2, default=lambda s: 8 + len(s["sid"]))),
                ("mask", FlagField(size=4, flag_type=AccessMask, flag_strict=False)),
                ("sid", StructureField(structure_type=SIDPacket)),
            ]
        )
        super().__init__()


class AccessDeniedAce(Structure):
    """
    [MS-DTYP] 2.4.4.4 ACCESS_DENIED_ACE

    Used for the DACL that controls denies to an object.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("ace_type", EnumField(size=1, default=AceType.ACCESS_DENIED_ACE_TYPE, enum_type=AceType)),
                ("ace_flags", FlagField(size=1, flag_type=AceFlags)),
                ("ace_size", IntField(size=2, default=lambda s: 8 + len(s["sid"]))),
                ("mask", FlagField(size=4, flag_type=AccessMask, flag_strict=False)),
                ("sid", StructureField(structure_type=SIDPacket)),
            ]
        )
        super().__init__()


class SystemAuditAce(Structure):
    """
    [MS-DTYP] 2.4.4.10 SYSTEM_AUDIT_ACE

    Used for the SACL that specifies what types of access cause system-level
    notifications.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("ace_type", EnumField(size=1, default=AceType.SYSTEM_AUDIT_ACE_TYPE, enum_type=AceType)),
                ("ace_flags", FlagField(size=1, flag_type=AceFlags)),
                ("ace_size", IntField(size=2, default=lambda s: 8 + len(s["sid"]))),
                ("mask", FlagField(size=4, flag_type=AccessMask, flag_strict=False)),
                ("sid", StructureField(structure_type=SIDPacket)),
            ]
        )
        super().__init__()


class AclPacket(Structure):
    """
    [MS-DTYP] 2.4.5 ACL

    Access Control List packet is used to specify a list of individual ACEs.
    An ACL is said to be in canonical form if:
        All explicit ACEs are placed before inherited ACEs
        Within the explicit ACEs, deny ACEs come before grant ACEs
        Deny ACEs on the object come before deny ACEs on a child or property
        Grant ACEs on the object come before grant ACEs on a child or property
        Inherited ACEs are placed in the order in which they were inherited
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("acl_revision", EnumField(size=1, default=AclRevision.ACL_REVISION, enum_type=AclRevision)),
                ("sbz1", IntField(size=1)),
                ("acl_size", IntField(size=2, default=lambda s: 8 + len(s["aces"]))),
                ("ace_count", IntField(size=2, default=lambda s: len(s["aces"].get_value()))),
                ("sbz2", IntField(size=2)),
                (
                    "aces",
                    ListField(
                        list_count=lambda s: s["ace_count"].get_value(),
                        unpack_func=AclPacket._unpack_aces,
                    ),
                ),
            ]
        )
        super().__init__()

    @staticmethod
    def _unpack_aces(structure, data):
        # The data handed in here is the ACE area of the ACL, i.e. the ACL
        # bytes beyond the 8 byte ACL header. Validate every boundary against
        # the declared AclSize/AceCount instead of silently truncating so a
        # malformed ACL is rejected rather than rewritten with lost content.
        acl_size = structure["acl_size"].get_value()
        ace_count = structure["ace_count"].get_value()
        ace_area_size = acl_size - ACL_HEADER_SIZE
        if acl_size < ACL_HEADER_SIZE or ace_area_size > len(data):
            raise MalformedSecurityDescriptor(
                f"ACL AclSize {acl_size} is invalid for the {len(data) + ACL_HEADER_SIZE} bytes of ACL data"
            )

        # Only the bytes covered by AclSize belong to this ACL. Anything beyond
        # it (e.g. the next component in the SD buffer) must not be consumed.
        remaining = data[:ace_area_size]
        aces = []

        for idx in range(ace_count):
            if len(remaining) < ACE_HEADER_SIZE:
                raise MalformedSecurityDescriptor(
                    f"ACL AceCount {ace_count} but only {len(aces)} complete ACE(s) fit inside AclSize {acl_size}"
                )

            ace_size = struct.unpack("<H", remaining[2:4])[0]
            if ace_size < ACE_HEADER_SIZE:
                raise MalformedSecurityDescriptor(
                    f"ACE {idx} has an AceSize of {ace_size} which is smaller than the minimum ACE header size"
                )
            if ace_size > len(remaining):
                raise MalformedSecurityDescriptor(
                    f"ACE {idx} AceSize {ace_size} exceeds the {len(remaining)} bytes remaining in the ACL"
                )

            ace_type = struct.unpack("<B", remaining[:1])[0]
            ace_struct = {
                AceType.ACCESS_ALLOWED_ACE_TYPE: AccessAllowedAce(),
                AceType.ACCESS_DENIED_ACE_TYPE: AccessDeniedAce(),
                AceType.SYSTEM_AUDIT_ACE_TYPE: SystemAuditAce(),
            }.get(ace_type, None)

            ace_data = remaining[:ace_size]
            if not ace_struct:
                # ACE types without a dedicated structure are preserved verbatim
                # so writing the ACL back does not mutate unrecognised ACEs.
                aces.append(ace_data)
            else:
                try:
                    ace_struct.unpack(ace_data)
                except (struct.error, IndexError) as err:
                    raise MalformedSecurityDescriptor(
                        f"ACE {idx} of type {ace_type} could not be parsed from its {ace_size} declared bytes: {err}"
                    )
                if len(ace_struct) != ace_size:
                    raise MalformedSecurityDescriptor(
                        f"ACE {idx} of type {ace_type} parsed to {len(ace_struct)} bytes but AceSize was {ace_size}"
                    )
                aces.append(ace_struct)

            remaining = remaining[ace_size:]

        if remaining != b"":
            # Trailing bytes inside AclSize that are not covered by any ACE
            # cannot be represented by the parsed structure and would be
            # dropped on rewrite, so reject the descriptor instead.
            raise MalformedSecurityDescriptor(
                f"ACL contains {len(remaining)} trailing byte(s) after the {ace_count} declared ACE(s)"
            )

        return aces


class SMB2CreateSDBuffer(Structure):
    """
    [MS-SMB2] 2.2.13.2.2 SMB2_CREATE_SD_BUFFER
    [MS-DTYP] 2.4.6 SECURITY_DESCRIPTOR

    Used to apply a security descriptor to a newly created file.

    A self-relative security descriptor distinguishes three states for the
    DACL (and SACL):

    * absent - the *PRESENT control flag is clear and there is no component,
    * NULL - the *PRESENT flag is set but the offset is 0 (a NULL DACL grants
      everyone access; a NULL SACL is treated as an empty SACL),
    * present - the *PRESENT flag is set and the offset points at a component.

    Use :meth:`is_dacl_present`/:meth:`is_dacl_null` (and the SACL variants) to
    tell them apart. A descriptor parsed from bytes indexes every component so a
    read-modify-write that only changes a single ACE repacks the untouched
    owner, group, other ACL and control flags losslessly.
    """

    def __init__(self):
        self.fields = OrderedDict(
            [
                ("revision", IntField(size=1, default=1)),
                ("sbz1", IntField(size=1)),
                ("control", FlagField(size=2, flag_type=SDControl)),
                ("offset_owner", IntField(size=4)),
                ("offset_group", IntField(size=4)),
                ("offset_sacl", IntField(size=4)),
                ("offset_dacl", IntField(size=4)),
                # buffer contains owner_sid, owner_group, sacl and dacl at
                # different offset, use get/set_* to get and set the individual
                # components instead of touching the buffer directly
                ("buffer", BytesField()),
            ]
        )
        # used to store the buffer values so it can easily be rebuilt. A value
        # of None marks a NULL ACL (present flag set, offset 0) while a missing
        # key marks an absent component (present flag clear).
        self._buffer = OrderedDict()
        super().__init__()

    def unpack(self, data):
        remaining = super().unpack(data)
        self._index_buffer()
        return remaining

    def get_owner(self):
        return self._get_sid_from_buffer("offset_owner")

    def set_owner(self, sid):
        if sid:
            self._buffer["owner"] = sid
        else:
            self._buffer.pop("owner", None)
        self._rebuild_buffer()

    def get_group(self):
        return self._get_sid_from_buffer("offset_group")

    def set_group(self, sid):
        if sid:
            self._buffer["group"] = sid
        else:
            self._buffer.pop("group", None)
        self._rebuild_buffer()

    def get_sacl(self):
        return self._get_acl_from_buffer("offset_sacl", SDControl.SACL_PRESENT)

    def set_sacl(self, acl):
        if acl:
            self["control"].set_flag(SDControl.SACL_PRESENT)
            self._buffer["sacl"] = acl
        else:
            self["control"].set_value(self["control"].get_value() & ~SDControl.SACL_PRESENT)
            self._buffer.pop("sacl", None)
        self._rebuild_buffer()

    def set_null_sacl(self):
        """Mark the SACL as a NULL ACL (SACL_PRESENT set, offset 0)."""
        self["control"].set_flag(SDControl.SACL_PRESENT)
        self._buffer["sacl"] = None
        self._rebuild_buffer()

    def is_sacl_present(self):
        return self["control"].has_flag(SDControl.SACL_PRESENT)

    def is_sacl_null(self):
        return self.is_sacl_present() and self["offset_sacl"].get_value() == 0

    def get_dacl(self):
        return self._get_acl_from_buffer("offset_dacl", SDControl.DACL_PRESENT)

    def set_dacl(self, acl):
        if acl:
            self["control"].set_flag(SDControl.DACL_PRESENT)
            self._buffer["dacl"] = acl
        else:
            self["control"].set_value(self["control"].get_value() & ~SDControl.DACL_PRESENT)
            self._buffer.pop("dacl", None)
        self._rebuild_buffer()

    def set_null_dacl(self):
        """Mark the DACL as a NULL DACL (DACL_PRESENT set, offset 0).

        A NULL DACL is very different from an absent DACL: it grants access to
        everyone. It is represented explicitly because :meth:`set_dacl` with
        ``None`` removes the DACL instead.
        """
        self["control"].set_flag(SDControl.DACL_PRESENT)
        self._buffer["dacl"] = None
        self._rebuild_buffer()

    def is_dacl_present(self):
        return self["control"].has_flag(SDControl.DACL_PRESENT)

    def is_dacl_null(self):
        return self.is_dacl_present() and self["offset_dacl"].get_value() == 0

    def _index_buffer(self):
        """Validate the on-wire layout and index every component for lossless rewrite."""
        buffer_data = self["buffer"].get_value()
        buffer_len = len(buffer_data)
        if not self["control"].has_flag(SDControl.SELF_RELATIVE):
            # An absolute (non self-relative) security descriptor uses pointers
            # instead of buffer offsets and never appears on the wire. Only the
            # header-only form can be parsed safely.
            if buffer_len != 0 or any(
                self[field].get_value() != 0
                for field in ("offset_owner", "offset_group", "offset_sacl", "offset_dacl")
            ):
                raise MalformedSecurityDescriptor(
                    "Only self-relative security descriptors (SELF_RELATIVE control flag) can contain a buffer"
                )
            self._buffer = OrderedDict()
            return
        specs = [
            ("owner", "offset_owner", None),
            ("group", "offset_group", None),
            ("sacl", "offset_sacl", SDControl.SACL_PRESENT),
            ("dacl", "offset_dacl", SDControl.DACL_PRESENT),
        ]

        indexed = []
        for name, offset_field, present_flag in specs:
            offset = self[offset_field].get_value()
            present = present_flag is None or self["control"].has_flag(present_flag)

            if not present:
                if offset != 0:
                    raise MalformedSecurityDescriptor(
                        f"{name} is absent in the control flags but {offset_field} is non-zero ({offset})"
                    )
                continue

            if offset == 0:
                # A NULL ACL/SID: present flag set with no component bytes.
                indexed.append((offset, name, None))
                continue

            if offset < SD_HEADER_SIZE:
                raise MalformedSecurityDescriptor(
                    f"{offset_field} {offset} points inside the security descriptor header"
                )

            relative_offset = offset - SD_HEADER_SIZE
            if relative_offset >= buffer_len:
                raise MalformedSecurityDescriptor(
                    f"{offset_field} {offset} is outside the {SD_HEADER_SIZE + buffer_len} byte security descriptor"
                )

            if name in ("sacl", "dacl"):
                component = self._parse_acl_component(name, buffer_data, relative_offset)
            else:
                component = self._parse_sid_component(name, buffer_data, relative_offset)

            indexed.append((offset, name, component))

        # Components must not overlap, otherwise a rewrite through the indexed
        # components could not preserve every byte.
        seen = []
        for offset, name, component in indexed:
            if component is None:
                continue
            end = offset + len(component.pack())
            for prev_offset, prev_name, prev_component in seen:
                prev_end = prev_offset + len(prev_component.pack())
                if offset < prev_end and prev_offset < end:
                    raise MalformedSecurityDescriptor(
                        f"Security descriptor components {name} and {prev_name} overlap in the buffer"
                    )
            seen.append((offset, name, component))

        # Rebuild the component index in the original on-wire order so an
        # untouched descriptor repacks to the same layout.
        self._buffer = OrderedDict()
        for offset, name, component in sorted(indexed, key=lambda entry: entry[0]):
            self._buffer[name] = component

    def _parse_acl_component(self, name, buffer_data, relative_offset):
        if relative_offset + ACL_HEADER_SIZE > len(buffer_data):
            raise MalformedSecurityDescriptor(f"{name} ACL does not contain a complete ACL header")

        acl_size = struct.unpack("<H", buffer_data[relative_offset + 2 : relative_offset + 4])[0]
        if acl_size < ACL_HEADER_SIZE:
            raise MalformedSecurityDescriptor(f"{name} ACL AclSize {acl_size} is smaller than the ACL header")
        if relative_offset + acl_size > len(buffer_data):
            raise MalformedSecurityDescriptor(
                f"{name} ACL AclSize {acl_size} extends beyond the security descriptor buffer"
            )

        acl = AclPacket()
        acl.unpack(buffer_data[relative_offset : relative_offset + acl_size])
        return acl

    def _parse_sid_component(self, name, buffer_data, relative_offset):
        # SID packet: 1 byte revision, 1 byte sub-authority count, 6 bytes of
        # identifier authority followed by 4 bytes per sub-authority.
        if relative_offset + 8 > len(buffer_data):
            raise MalformedSecurityDescriptor(f"{name} SID does not contain a complete SID header")

        sub_authority_count = buffer_data[relative_offset + 1]
        sid_size = 8 + (4 * sub_authority_count)
        if relative_offset + sid_size > len(buffer_data):
            raise MalformedSecurityDescriptor(
                f"{name} SID declares {sub_authority_count} sub-authorities but the buffer is too short"
            )

        sid = SIDPacket()
        sid.unpack(buffer_data[relative_offset : relative_offset + sid_size])
        return sid

    def _get_sid_from_buffer(self, offset_field):
        offset = self[offset_field].get_value()
        if offset == 0:
            return None

        buffer_data = self["buffer"].get_value()[offset - SD_HEADER_SIZE :]
        sid = SIDPacket()
        sid.unpack(buffer_data)
        return sid

    def _get_acl_from_buffer(self, offset_field, flag):
        if not self["control"].has_flag(flag):
            return None

        offset = self[offset_field].get_value()
        if offset == 0:
            # NULL ACL: the present flag is set but there is no ACL body.
            return None

        relative_offset = offset - SD_HEADER_SIZE
        buffer_data = self["buffer"].get_value()[relative_offset:]
        length = struct.unpack("<H", buffer_data[2:4])[0]
        data = buffer_data[:length]
        acl = AclPacket()
        acl.unpack(data)
        return acl

    def _rebuild_buffer(self):
        buffer = b""
        offset_count = SD_HEADER_SIZE

        for field, value in self._buffer.items():
            if value is None:
                # NULL component: present flag stays set, the offset remains 0.
                self[f"offset_{field}"].set_value(0)
                continue
            offset_field = f"offset_{field}"
            field_bytes = value.pack()
            buffer += field_bytes
            self[offset_field].set_value(offset_count)
            offset_count += len(field_bytes)

        self["buffer"].set_value(buffer)
