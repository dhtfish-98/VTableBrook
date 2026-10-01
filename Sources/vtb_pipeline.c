#include "vtb_image_layout.h"

void
vtb_review_image(const struct mach_header_64 *vtb_binding_072, uint64_t vtb_binding_073) {
	const struct section_64 *vtb_binding_074, *vtb_binding_075, *vtb_binding_076;
	const struct segment_command_64 *vtb_binding_077;
	const uint64_t *vtb_binding_078;
	uint64_t vtb_binding_079, vtb_binding_080, vtb_binding_081, vtb_binding_082;
	
	if((vtb_binding_076 = vtb_region_section_kind(vtb_binding_072, SEG_DATA, S_MOD_INIT_FUNC_POINTERS)) &&
	   (vtb_binding_077 = vtb_locate_region(vtb_binding_072, SEG_TEXT)) &&
	   (vtb_binding_075 = vtb_locate_section_kind(vtb_binding_077, S_CSTRING_LITERALS)) &&
	   (vtb_binding_074 = vtb_region_section_label(vtb_binding_072, "__TEXT_EXEC", SECT_TEXT)))
	{
		vtb_binding_081 = vtb_binding_074->addr + vtb_binding_074->size;
		if((vtb_binding_082 = vtb_discover_metaclass(vtb_binding_072, vtb_binding_077->vmaddr, vtb_binding_081))) {
			vtb_binding_078 = (const uint64_t *)((uintptr_t)vtb_binding_072 + vtb_binding_076->offset);
			vtb_binding_080 = vtb_binding_075->addr + vtb_binding_075->size;
			
			for(vtb_binding_079 = 0; vtb_binding_079 < vtb_binding_076->size / sizeof(*vtb_binding_078); ++vtb_binding_079) {
				vtb_inspect_initializer(vtb_binding_072, vtb_binding_073, VTB_RULE_04(vtb_binding_078[vtb_binding_079]), vtb_binding_077->vmaddr, vtb_binding_075->addr, vtb_binding_080, vtb_binding_074->addr, vtb_binding_081, vtb_binding_082);
			}
		}
	}
}
