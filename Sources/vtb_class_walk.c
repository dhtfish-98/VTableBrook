#include "vtb_image_layout.h"

/* This is a bounded pattern interpreter, not execution or a complete ARM64 emulator. */
static int64_t vtb_signed_field(uint32_t field, unsigned bits) {
    uint64_t sign = UINT64_C(1) << (bits - 1);
    return (int64_t)(field & (sign - 1)) - (int64_t)(field & sign);
}

static bool vtb_branch(uint32_t word) { return (word & 0xfc000000u) == 0x94000000u; }
static bool vtb_store(uint32_t word) { return (word & 0xfffffc00u) == 0xf9000000u; }
static bool vtb_return(uint32_t word) { return word == 0xd65f03c0u; }
static uint64_t vtb_branch_target(uint64_t pc, uint32_t word) {
    /* Unsigned addition intentionally models the 64-bit architectural result. */
    return pc + (uint64_t)(vtb_signed_field(word & 0x03ffffffu, 26) * 4);
}

static bool vtb_logical_mask(uint32_t word, uint32_t *mask) {
    unsigned imms = (word >> 10) & 63u, immr = (word >> 16) & 63u;
    unsigned selector = (~imms) & 63u, width = 0, run, rotation, bit;
    uint32_t result = 0;
    /* W-register ORR requires N=0 and a non-all-ones element. */
    if (word & (1u << 22)) return false;
    for (bit = 1; bit <= 5; ++bit) if (selector & (1u << bit)) width = 1u << bit;
    if (!width) return false;
    run = (imms & (width - 1)) + 1;
    if (run == width) return false;
    rotation = immr & (width - 1);
    for (bit = 0; bit < 32; ++bit)
        if (((bit + rotation) & (width - 1)) < run) result |= UINT32_C(1) << bit;
    *mask = result;
    return true;
}

static void vtb_register_step(struct vtb_registers *registers, uint64_t pc, uint32_t word) {
    unsigned destination = word & 31u, source = (word >> 5) & 31u;
    uint64_t value;
    bool known;
    if ((word & 0x9f000000u) == 0x90000000u) {
        uint32_t encoded = (((word >> 5) & 0x7ffffu) << 2) | ((word >> 29) & 3u);
        value = (pc & ~UINT64_C(0xfff)) + (uint64_t)(vtb_signed_field(encoded, 21) * 4096);
        if (destination != 31) { registers->value[destination] = value; registers->known[destination] = true; }
    } else if ((word & 0xff800000u) == 0x91000000u) {
        uint64_t immediate = (word >> 10) & 0xfffu;
        if (word & (1u << 22)) immediate *= 4096;
        registers->value[destination] = registers->value[source] + immediate;
        registers->known[destination] = registers->known[source]; /* register 31 is SP here */
    } else if ((word & 0xff800000u) == 0x52800000u || (word & 0xff800000u) == 0xd2800000u) {
        unsigned shift = ((word >> 21) & 3u) * 16;
        bool wide = (word >> 31) != 0;
        if (destination == 31) return;
        registers->known[destination] = wide || shift < 32;
        registers->value[destination] = (uint64_t)((word >> 5) & 0xffffu) << shift;
    } else if ((word & 0xffe0ffe0u) == 0xaa0003e0u) {
        /* MOV Xd, Xm (ORR Xd, XZR, Xm, LSL #0), not arbitrary ORR. */
        source = (word >> 16) & 31u;
        if (destination == 31) return;
        registers->known[destination] = source == 31 || registers->known[source];
        registers->value[destination] = source == 31 ? 0 : registers->value[source];
    } else if ((word & 0xff800000u) == 0x32000000u) {
        uint32_t mask;
        if (destination == 31) return;
        known = vtb_logical_mask(word, &mask) && (source == 31 || registers->known[source]);
        value = source == 31 ? 0 : (uint32_t)registers->value[source];
        registers->known[destination] = known;
        if (known) registers->value[destination] = (uint32_t)value | mask;
    }
}

bool vtb_discover_metaclass(struct vtb_image *image, uint64_t *constructor) {
    uint64_t pointer;
    size_t offset;
    *constructor = 0;
    if (image->bootstrap.length < 16) return vtb_fail(image, "bootstrap table needs two pointer entries");
    pointer = vtb_read_u64(image->bytes + image->bootstrap.offset + 8);
    if (!pointer) return true;
    pointer = vtb_normalize_pointer(pointer);
    if (!vtb_code_start(image, pointer, &offset)) return false;
    for (; offset < image->code.length; offset += 4) {
        uint32_t word;
        if (!vtb_next_instruction(image, offset, &word)) return false;
        if (vtb_branch(word)) {
            uint64_t target = vtb_branch_target(image->code.address + offset, word);
            size_t checked;
            if (!vtb_code_start(image, target, &checked)) return false;
            *constructor = target;
            return true;
        }
        if (vtb_return(word)) break;
    }
    return true;
}

static bool vtb_inspect_allocation(struct vtb_image *image, uint64_t start,
                                   struct vtb_allocation *allocation) {
    size_t offset;
    struct vtb_registers registers = {{0}, {false}};
    if (!vtb_code_start(image, start, &offset)) return false;
    for (; offset < image->code.length; offset += 4) {
        uint32_t word;
        if (!vtb_next_instruction(image, offset, &word)) return false;
        if (vtb_store(word)) {
            unsigned source = word & 31u;
            if ((source == 31 || registers.known[source]) && registers.known[0]) {
                allocation->found = true;
                allocation->table = source == 31 ? 0 : registers.value[source];
                allocation->size = registers.value[0];
            }
            break;
        }
        if (vtb_return(word)) break;
        vtb_register_step(&registers, image->code.address + offset, word);
    }
    return true;
}

static bool vtb_emit_record(struct vtb_image *image, uint64_t name, uint64_t metaclass) {
    const unsigned char *text, *end, *table;
    size_t length, i;
    uint64_t allocator, encoded_length = 0;
    struct vtb_allocation allocation = {false, 0, 0};
    char suffix[160];
    int suffix_length;
    if (name < image->names.address || name - image->names.address >= image->names.length) return true;
    text = image->bytes + image->names.offset + (size_t)(name - image->names.address);
    length = (size_t)(image->names.length - (name - image->names.address));
    if (length > VTB_MAX_NAME_BYTES + 1u) length = VTB_MAX_NAME_BYTES + 1u;
    end = memchr(text, 0, length);
    if (!end) return vtb_fail(image, "class name is unterminated or exceeds 64 KiB");
    length = (size_t)(end - text);
    if (metaclass % 8 || !vtb_linear_bytes(image, metaclass, 13 * 8, &table))
        return vtb_fail(image, "metaclass table needs thirteen aligned pointer entries");
    allocator = vtb_read_u64(table + 12 * 8);
    if (allocator) {
        allocator = vtb_normalize_pointer(allocator);
        if (allocator >= image->code.address && allocator - image->code.address < image->code.length &&
            !vtb_inspect_allocation(image, allocator, &allocation)) return false;
    }
    if (allocation.found)
        suffix_length = snprintf(suffix, sizeof(suffix), ", metaclass: 0x%016" PRIx64
            ", vtable: 0x%016" PRIx64 ", size: 0x%" PRIx64 "\n", metaclass, allocation.table, allocation.size);
    else suffix_length = snprintf(suffix, sizeof(suffix), ", metaclass: 0x%016" PRIx64 "\n", metaclass);
    if (suffix_length < 0 || (size_t)suffix_length >= sizeof(suffix)) return vtb_fail(image, "cannot format record");
    for (i = 0; i < length; ++i) encoded_length += text[i] >= 32 && text[i] <= 126 && text[i] != '\\' ? 1 : 4;
    encoded_length += 6 + (unsigned)suffix_length;
    if (image->records >= VTB_MAX_RECORDS || encoded_length > VTB_MAX_OUTPUT_BYTES - image->output_bytes)
        return vtb_fail(image, "record or output limit exceeded; analysis is incomplete");
    ++image->records;
    image->output_bytes += encoded_length;
    fputs("Name: ", stdout);
    for (i = 0; i < length; ++i) {
        if (text[i] >= 32 && text[i] <= 126 && text[i] != '\\') putchar(text[i]);
        else printf("\\x%02x", text[i]);
    }
    fputs(suffix, stdout);
    return true;
}

bool vtb_inspect_initializer(struct vtb_image *image, uint64_t start, uint64_t constructor) {
    size_t offset;
    bool called_constructor = false;
    struct vtb_registers registers = {{0}, {false}};
    if (!vtb_code_start(image, start, &offset)) return false;
    for (; offset < image->code.length; offset += 4) {
        uint32_t word;
        if (!vtb_next_instruction(image, offset, &word)) return false;
        if (vtb_branch(word)) {
            called_constructor = vtb_branch_target(image->code.address + offset, word) == constructor;
        } else if (called_constructor && vtb_store(word)) {
            unsigned source = word & 31u;
            if (registers.known[1] && (source == 31 || registers.known[source]) &&
                !vtb_emit_record(image, registers.value[1], source == 31 ? 0 : registers.value[source])) return false;
            called_constructor = false;
        } else if (vtb_return(word)) break;
        else vtb_register_step(&registers, image->code.address + offset, word);
    }
    return true;
}
