meta:
  id: rtpatch_file
  title: RTPatch file
  file-extension: rtp
  endian: le
  encoding: ISO-8859-1
  license: CC0-1.0
doc: |
  The schema models the shared package header, optional root list, optional
  legacy banner block, modern type 0x5000 records with bounded trailing history
  data, legacy type 0x4000 patch records, and type 0x2000 direct payload
  records in both modern and legacy forms.

seq:
  - id: magic
    contents: [0x4b, 0x2a]
  - id: version
    type: u2le
  - id: flags
    type: u2le
  - id: engine_flags
    type: u4le
    if: (flags & 0x8000) != 0
  - id: package_flags
    type: u2le
  - id: header_unk0
    type: u4le
  - id: header_unk1
    type: u4le
  - id: header_unk2
    type: u2le
  - id: header_unk3
    type: u2le
  - id: string_flags
    type: u2le
  - id: header_unk4
    type: u4le
    if: (string_flags & 0x4) != 0
  - id: header_unk5
    type: u4le
  - id: roots
    type: roots_block
    if: (flags & 0x0200) != 0
  - id: record_section
    type: record_section
    size-eos: true

instances:
  legacy_banner:
    value: record_section.legacy_banner
    if: record_section.has_legacy_banner
  records:
    value: record_section.records

types:
  record_section:
    seq:
      - id: legacy_banner
        type: legacy_banner
        if: has_legacy_banner
      - id: records
        type: record
        repeat: until
        repeat-until: _.is_terminator
      - id: trailer
        size-eos: true
    instances:
      first_flags:
        pos: 0
        type: u2le
      banner_line_count:
        pos: 0
        type: u2le
      banner_candidate_offset:
        value: 2 + (banner_line_count * 37)
      banner_candidate_flags:
        pos: banner_candidate_offset
        type: u2le
        if: banner_candidate_offset + 2 <= _io.size
      first_looks_like_record:
        value: ((first_flags & 0xF000) == 0x1000) or ((first_flags & 0xF000) == 0x2000) or ((first_flags & 0xF000) == 0x4000) or ((first_flags & 0xF000) == 0x5000)
      candidate_looks_like_record:
        value: (banner_candidate_offset + 2 <= _io.size) and ((((banner_candidate_flags & 0xF000) == 0x1000) or ((banner_candidate_flags & 0xF000) == 0x2000) or ((banner_candidate_flags & 0xF000) == 0x4000) or ((banner_candidate_flags & 0xF000) == 0x5000)))
      has_legacy_banner:
        value: (_io.size >= 2) and (not first_looks_like_record) and (banner_line_count != 0) and candidate_looks_like_record

  legacy_banner:
    seq:
      - id: num_lines
        type: u2le
      - id: lines
        type: legacy_banner_line
        repeat: expr
        repeat-expr: num_lines

  legacy_banner_line:
    seq:
      - id: raw
        size: 37

  roots_block:
    seq:
      - id: num_roots
        type: u2le
      - id: roots
        type: package_string
        repeat: expr
        repeat-expr: num_roots

  package_string:
    seq:
      - id: len_value
        type: u1
      - id: value
        type: str
        size: len_value
        encoding: ISO-8859-1

  len_prefixed_cstring:
    seq:
      - id: len_value
        type: u1
      - id: value
        size: len_value

  fixed_cstring_14:
    seq:
      - id: value
        size: 14

  varint:
    doc: |
      RTPatch variable-length integer encoding used in record prefixes and the
      instruction stream.
    seq:
      - id: b0
        type: u1
      - id: b1
        type: u1
        if: extra_byte_count >= 1
      - id: b2
        type: u1
        if: extra_byte_count >= 2
      - id: b3
        type: u1
        if: extra_byte_count >= 3
      - id: b4
        type: u1
        if: extra_byte_count >= 4
      - id: b5
        type: u1
        if: extra_byte_count >= 5
      - id: b6
        type: u1
        if: extra_byte_count >= 6
      - id: b7
        type: u1
        if: extra_byte_count >= 7
    instances:
      extra_byte_count:
        value: '((b0 & 0x40) == 0) ? 0 : (((b0 & 0x20) == 0) ? 1 : (((b0 & 0x10) == 0) ? 2 : (((b0 & 0x08) == 0) ? 3 : (((b0 & 0x04) == 0) ? 4 : (((b0 & 0x02) == 0) ? 5 : (((b0 & 0x01) == 0) ? 6 : 7))))))'

  record:
    seq:
      - id: flags
        type: u2le
      - id: subflags
        type: u2le
        if: (flags & 0x2) != 0
      - id: path
        type: package_string
        if: (flags & 0x4) != 0
      - id: delta_1
        type: varint
        if: (((flags & 0x2) != 0) and ((subflags & 0xC0) != 0)) or (((flags & 0x2) == 0) and ((_root.package_flags & 0xC0) != 0))
      - id: delta_2
        type: varint
        if: ((((flags & 0x2) != 0) and ((subflags & 0xC0) != 0)) or (((flags & 0x2) == 0) and ((_root.package_flags & 0xC0) != 0))) and ((_root.flags & 0x8000) != 0) and ((_root.engine_flags & 0x7) == 0) and ((_root.engine_flags & 0x10000) != 0)
      - id: extra_varint
        type: varint
        if: (flags & 0x80) != 0
      - id: extra_u16
        type: u2le
        if: (flags & 0x100) != 0
      - id: extra_paths
        type: package_string
        repeat: expr
        repeat-expr: 2
        if: (flags & 0x200) != 0 and (record_type != 0x5000)
      - id: body
        type:
          switch-on: record_type
          cases:
            0x1000: record_terminator
            0x2000: record_2000_body
            0x4000: record_4000_body
            0x5000: record_5000_body
    instances:
      record_type:
        value: flags & 0xF000
      is_terminator:
        value: record_type == 0x1000
      uses_legacy_layout:
        value: _parent.has_legacy_banner

  record_terminator:
    seq: []

  record_2000_body:
    seq:
      - id: path_selector
        size: 10
      - id: inline_kind
        type: varint
      - id: output_size
        type: u4le
      - id: len_payload
        type: u4le
      - id: short_name
        type: fixed_cstring_14
      - id: file_attributes
        type: u2le
      - id: repeated_output_size
        type: u4le
      - id: unknown_4
        size: 4
      - id: checksum
        size: 10
      - id: legacy_padding
        size: 8
        if: not _parent.uses_legacy_layout
      - id: name
        type: len_prefixed_cstring
        if: not _parent.uses_legacy_layout
      - id: payload
        size: len_payload

  record_4000_body:
    seq:
      - id: unknown_10
        size: 10
      - id: variant_flags
        type: u2le
      - id: inline_kind
        type: u2le
      - id: output_size
        type: u4le
      - id: len_payload
        type: u4le
      - id: primary_entry
        type: legacy_record_entry
      - id: secondary_entry
        type: legacy_record_entry
      - id: payload
        size: len_payload

  legacy_record_entry:
    seq:
      - id: short_name
        type: fixed_cstring_14
      - id: file_attributes
        type: u2le
      - id: size_hint
        type: u4le
      - id: unknown_4
        size: 4
      - id: checksum
        size: 10

  record_5000_body:
    seq:
      - id: prelude
        type: record_5000_prelude
      - id: content
        type: record_5000_content
        size: prelude.rel_next

  record_5000_prelude:
    seq:
      - id: rel_next
        type: u4le
      - id: history_version_count
        type: u2le
      - id: unknown_10
        size: 10

  record_5000_content:
    seq:
      - id: header_kind
        type: u2le
      - id: header
        type:
          switch-on: header_kind
          cases:
            0x02C2: record_5000_direct_header
            0x02C4: record_5000_patch_header
      - id: output_size
        type: u4le
      - id: len_payload
        type: u4le
      - id: primary_entry
        type: record_5000_entry
      - id: secondary_entry
        type: record_5000_entry
        if: header_kind == 0x02C4
      - id: payload
        size: len_payload
      - id: trailer
        size-eos: true

  record_5000_direct_header:
    seq:
      - id: inline_kind
        type: u1

  record_5000_patch_header:
    seq:
      - id: variant_flags
        type: u2le
      - id: inline_kind
        type: u2le

  record_5000_entry:
    seq:
      - id: short_name
        type: fixed_cstring_14
      - id: file_attributes
        type: u2le
      - id: size_hint
        type: u4le
      - id: unknown_4
        size: 4
      - id: checksum
        size: 10
      - id: unknown_8
        size: 8
      - id: name
        type: len_prefixed_cstring
