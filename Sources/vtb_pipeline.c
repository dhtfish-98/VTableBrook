#include "vtb_image_layout.h"

bool vtb_review_image(struct vtb_image *image) {
    uint64_t constructor, i;
    if (!vtb_parse_container(image)) return false;
    if (!image->has_base || !image->initializers.present || !image->bootstrap.present ||
        !image->names.present || !image->code.present) return true;
    if (!vtb_discover_metaclass(image, &constructor)) return false;
    if (!constructor) return true;
    for (i = 0; i < image->initializers.length / 8; ++i) {
        uint64_t pointer = vtb_read_u64(image->bytes + image->initializers.offset + (size_t)i * 8);
        if (pointer && !vtb_inspect_initializer(image, vtb_normalize_pointer(pointer), constructor))
            return false;
    }
    return true;
}
