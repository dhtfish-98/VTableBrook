#include "vtb_image_layout.h"

static bool vtb_label(const char field[16], const char *expected) {
    return strncmp(field, expected, 16) == 0;
}

static bool vtb_select_span(struct vtb_image *image, struct vtb_span *span,
                            const struct section_64 *section) {
    if (span->present) return vtb_fail(image, "ambiguous analysis section");
    span->address = section->addr;
    span->length = section->size;
    span->offset = section->offset;
    span->present = true;
    return true;
}

static bool vtb_parse_segment(struct vtb_image *image, size_t position,
                               uint32_t command_size, unsigned *section_count) {
    struct segment_command_64 segment;
    size_t i, cursor;
    if (command_size < sizeof(segment))
        return vtb_fail(image, "short segment command");
    memcpy(&segment, image->bytes + position, sizeof(segment));
    if (segment.nsects > (command_size - sizeof(segment)) / sizeof(struct section_64))
        return vtb_fail(image, "sections exceed their load command");
    if (segment.nsects > VTB_MAX_SECTIONS - *section_count)
        return vtb_fail(image, "section limit exceeded");
    *section_count += segment.nsects;
    if (!vtb_address_range(segment.vmaddr, segment.vmsize) ||
        !vtb_file_range(image->length, segment.fileoff, segment.filesize))
        return vtb_fail(image, "segment range exceeds the image");
    if (vtb_label(segment.segname, SEG_TEXT)) {
        if (image->has_base) return vtb_fail(image, "ambiguous __TEXT base");
        image->base = segment.vmaddr;
        image->has_base = true;
    }
    cursor = position + sizeof(segment);
    for (i = 0; i < segment.nsects; ++i, cursor += sizeof(struct section_64)) {
        struct section_64 section;
        unsigned kind;
        bool zero_fill;
        memcpy(&section, image->bytes + cursor, sizeof(section));
        kind = section.flags & SECTION_TYPE;
        zero_fill = kind == S_ZEROFILL || kind == S_GB_ZEROFILL ||
                    kind == S_THREAD_LOCAL_ZEROFILL;
        if (memcmp(section.segname, segment.segname, sizeof(section.segname)) != 0 ||
            !vtb_address_range(section.addr, section.size) ||
            (!zero_fill && !vtb_file_range(image->length, section.offset, section.size)))
            return vtb_fail(image, "invalid section name or range");
        if (vtb_label(segment.segname, SEG_DATA) && kind == S_MOD_INIT_FUNC_POINTERS) {
            if (!vtb_select_span(image, &image->initializers, &section)) return false;
        } else if (vtb_label(segment.segname, "__DATA_CONST") && kind == S_MOD_INIT_FUNC_POINTERS) {
            if (!vtb_select_span(image, &image->bootstrap, &section)) return false;
        } else if (vtb_label(segment.segname, SEG_TEXT) && kind == S_CSTRING_LITERALS) {
            if (!vtb_select_span(image, &image->names, &section)) return false;
        } else if (vtb_label(segment.segname, "__TEXT_EXEC") && vtb_label(section.sectname, SECT_TEXT)) {
            if (zero_fill) return vtb_fail(image, "code section has no file bytes");
            if (!vtb_select_span(image, &image->code, &section)) return false;
        }
    }
    return true;
}

bool vtb_parse_container(struct vtb_image *image) {
    struct mach_header_64 header;
    size_t cursor = sizeof(header), end;
    uint32_t i;
    unsigned sections = 0;
    struct vtb_span *spans[] = {
        &image->initializers, &image->bootstrap, &image->names, &image->code
    };
    if (image->length < sizeof(header)) return vtb_fail(image, "short Mach-O header");
    memcpy(&header, image->bytes, sizeof(header));
    if (header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64)
        return vtb_fail(image, "expected a little-endian ARM64 Mach-O image");
    if (header.ncmds > VTB_MAX_COMMANDS || header.ncmds > header.sizeofcmds / sizeof(struct load_command) ||
        !vtb_file_range(image->length, cursor, header.sizeofcmds))
        return vtb_fail(image, "invalid load-command area or command limit");
    end = cursor + header.sizeofcmds;
    for (i = 0; i < header.ncmds; ++i) {
        struct load_command command;
        if (!vtb_file_range(end, cursor, sizeof(command)))
            return vtb_fail(image, "short load command");
        memcpy(&command, image->bytes + cursor, sizeof(command));
        if (command.cmdsize < sizeof(command) || command.cmdsize % 8 != 0 ||
            !vtb_file_range(end, cursor, command.cmdsize))
            return vtb_fail(image, "invalid load-command size");
        if (command.cmd == LC_SEGMENT_64 &&
            !vtb_parse_segment(image, cursor, command.cmdsize, &sections)) return false;
        cursor += command.cmdsize;
    }
    if (cursor != end) return vtb_fail(image, "load-command count and area disagree");
    if (!image->has_base) return true;
    for (i = 0; i < sizeof(spans) / sizeof(spans[0]); ++i) {
        struct vtb_span *span = spans[i];
        if (span->present && (span->address < image->base ||
            span->address - image->base != span->offset))
            return vtb_fail(image, "unsupported non-linear kernel layout");
    }
    if ((image->code.present && (image->code.address % 4 || image->code.length % 4)) ||
        (image->initializers.present && image->initializers.length % 8) ||
        (image->bootstrap.present && image->bootstrap.length % 8))
        return vtb_fail(image, "misaligned code or initializer length");
    if (image->initializers.length / 8 > VTB_MAX_INITIALIZERS)
        return vtb_fail(image, "initializer limit exceeded");
    return true;
}

bool vtb_linear_bytes(struct vtb_image *image, uint64_t address, size_t length,
                      const unsigned char **bytes) {
    if (!image->has_base || address < image->base ||
        !vtb_file_range(image->length, address - image->base, length))
        return vtb_fail(image, "metadata pointer exceeds the file");
    *bytes = image->bytes + (size_t)(address - image->base);
    return true;
}

bool vtb_code_start(struct vtb_image *image, uint64_t address, size_t *offset) {
    if (!image->code.present || address % 4 || address < image->code.address ||
        address - image->code.address >= image->code.length)
        return vtb_fail(image, "initializer or allocator is outside the code section");
    *offset = (size_t)(address - image->code.address);
    return true;
}

bool vtb_next_instruction(struct vtb_image *image, size_t offset, uint32_t *word) {
    if (!vtb_file_range((size_t)image->code.length, offset, 4))
        return vtb_fail(image, "instruction exceeds the code section");
    if (image->instructions >= VTB_MAX_INSTRUCTIONS)
        return vtb_fail(image, "instruction limit exceeded; analysis is incomplete");
    ++image->instructions;
    *word = vtb_read_u32(image->bytes + image->code.offset + offset);
    return true;
}
