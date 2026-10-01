#include "vtb_image_layout.h"

const struct segment_command_64 *
vtb_locate_region(const struct mach_header_64 *vtb_binding_013, const char *vtb_binding_014) {
	const struct segment_command_64 *vtb_binding_015 = (const struct segment_command_64 *)((uintptr_t)vtb_binding_013 + sizeof(*vtb_binding_013));
	uint32_t vtb_binding_016;
	
	for(vtb_binding_016 = 0; vtb_binding_016 < vtb_binding_013->ncmds; ++vtb_binding_016) {
		if(vtb_binding_015->cmd == LC_SEGMENT_64 && !strncmp(vtb_binding_015->segname, vtb_binding_014, sizeof(vtb_binding_015->segname))) {
			return vtb_binding_015;
		}
		vtb_binding_015 = (const struct segment_command_64 *)((uintptr_t)vtb_binding_015 + vtb_binding_015->cmdsize);
	}
	return NULL;
}

const struct section_64 *
vtb_locate_section_kind(const struct segment_command_64 *vtb_binding_018, uint8_t vtb_binding_019) {
	const struct section_64 *vtb_binding_020 = (const struct section_64 *)((uintptr_t)vtb_binding_018 + sizeof(*vtb_binding_018));
	uint32_t vtb_binding_021;
	
	for(vtb_binding_021 = 0; vtb_binding_021 < vtb_binding_018->nsects; ++vtb_binding_021) {
		if((vtb_binding_020->flags & SECTION_TYPE) == vtb_binding_019) {
			return vtb_binding_020;
		}
		++vtb_binding_020;
	}
	return NULL;
}

const struct section_64 *
vtb_locate_section_label(const struct segment_command_64 *vtb_binding_023, const char *vtb_binding_024) {
	const struct section_64 *vtb_binding_025 = (const struct section_64 *)((uintptr_t)vtb_binding_023 + sizeof(*vtb_binding_023));
	uint32_t vtb_binding_026;
	
	for(vtb_binding_026 = 0; vtb_binding_026 < vtb_binding_023->nsects; ++vtb_binding_026) {
		if(!strncmp(vtb_binding_025->segname, vtb_binding_023->segname, sizeof(vtb_binding_025->segname)) && !strncmp(vtb_binding_025->sectname, vtb_binding_024, sizeof(vtb_binding_025->sectname))) {
			return vtb_binding_025;
		}
		++vtb_binding_025;
	}
	return NULL;
}

const struct section_64 *
vtb_region_section_kind(const struct mach_header_64 *vtb_binding_028, const char *vtb_binding_029, uint8_t vtb_binding_030) {
	const struct segment_command_64 *vtb_binding_031;
	
	if((vtb_binding_031 = vtb_locate_region(vtb_binding_028, vtb_binding_029))) {
		return vtb_locate_section_kind(vtb_binding_031, vtb_binding_030);
	}
	return NULL;
}

const struct section_64 *
vtb_region_section_label(const struct mach_header_64 *vtb_binding_033, const char *vtb_binding_034, const char *vtb_binding_035) {
	const struct segment_command_64 *vtb_binding_036;
	
	if((vtb_binding_036 = vtb_locate_region(vtb_binding_033, vtb_binding_034))) {
		return vtb_locate_section_label(vtb_binding_036, vtb_binding_035);
	}
	return NULL;
}
