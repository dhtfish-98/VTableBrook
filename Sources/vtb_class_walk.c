#include "vtb_image_layout.h"

uint64_t
vtb_discover_metaclass(const struct mach_header_64 *vtb_binding_038, uint64_t vtb_binding_039, uint64_t vtb_binding_040) {
	const struct section_64 *vtb_binding_041;
	const uint64_t *vtb_binding_042;
	const uint32_t *vtb_binding_043;
	uint64_t vtb_binding_044, vtb_binding_045;
	
	if((vtb_binding_041 = vtb_region_section_kind(vtb_binding_038, "__DATA_CONST", S_MOD_INIT_FUNC_POINTERS))) {
		vtb_binding_042 = (const uint64_t *)((uintptr_t)vtb_binding_038 + (VTB_RULE_04(vtb_binding_041->addr) - vtb_binding_039));
		vtb_binding_045 = VTB_RULE_04(vtb_binding_042[VTB_RULE_01]);
		vtb_binding_043 = (const uint32_t *)((uintptr_t)vtb_binding_038 + (vtb_binding_045 - vtb_binding_039));
		for(vtb_binding_044 = 0; vtb_binding_044 < (vtb_binding_040 - vtb_binding_045) / sizeof(*vtb_binding_043); ++vtb_binding_044) {
			if(VTB_RULE_08(vtb_binding_043[vtb_binding_044])) {
				return vtb_binding_045 + (vtb_binding_044 * sizeof(*vtb_binding_043)) + VTB_RULE_09(vtb_binding_043[vtb_binding_044]);
			}
		}
	}
	return 0;
}

void
vtb_inspect_allocation(const struct mach_header_64 *vtb_binding_047, uint64_t vtb_binding_048, uint64_t vtb_binding_049, uint64_t vtb_binding_050) {
	const uint32_t *vtb_binding_051;
	uint64_t vtb_binding_052, vtb_binding_053[32] = { 0 };
	
	vtb_binding_051 = (const uint32_t *)((uintptr_t)vtb_binding_047 + (vtb_binding_048 - vtb_binding_049));
	for(vtb_binding_052 = 0; vtb_binding_052 < (vtb_binding_050 - vtb_binding_048) / sizeof(*vtb_binding_051); ++vtb_binding_052) {
		if(VTB_RULE_10(vtb_binding_051[vtb_binding_052])) {
			vtb_binding_053[VTB_RULE_05(vtb_binding_051[vtb_binding_052])] = VTB_RULE_12(vtb_binding_048 + (vtb_binding_052 * sizeof(*vtb_binding_051))) + VTB_RULE_11(vtb_binding_051[vtb_binding_052]);
		} else if(VTB_RULE_13(vtb_binding_051[vtb_binding_052])) {
			vtb_binding_053[VTB_RULE_05(vtb_binding_051[vtb_binding_052])] = vtb_binding_053[VTB_RULE_07(vtb_binding_051[vtb_binding_052])] + VTB_RULE_14(vtb_binding_051[vtb_binding_052]);
		} else if(VTB_RULE_20(vtb_binding_051[vtb_binding_052])) {
			vtb_binding_053[VTB_RULE_05(vtb_binding_051[vtb_binding_052])] = VTB_RULE_21(vtb_binding_051[vtb_binding_052]);
		} else if(VTB_RULE_17(vtb_binding_051[vtb_binding_052])) {
			vtb_binding_053[VTB_RULE_05(vtb_binding_051[vtb_binding_052])] = vtb_binding_053[VTB_RULE_07(vtb_binding_051[vtb_binding_052])] | VTB_RULE_19(vtb_binding_051[vtb_binding_052]);
		} else if(VTB_RULE_15(vtb_binding_051[vtb_binding_052])) {
			printf(", vtable: 0x%016" PRIx64 ", size: 0x%" PRIx64, vtb_binding_053[VTB_RULE_05(vtb_binding_051[vtb_binding_052])], vtb_binding_053[0]);
			break;
		} else if(VTB_RULE_22(vtb_binding_051[vtb_binding_052])) {
			break;
		}
	}
}

void
vtb_inspect_initializer(const struct mach_header_64 *vtb_binding_055, uint64_t vtb_binding_056, uint64_t vtb_binding_057, uint64_t vtb_binding_058, uint64_t vtb_binding_059, uint64_t vtb_binding_060, uint64_t vtb_binding_061, uint64_t vtb_binding_062, uint64_t vtb_binding_063) {
	const uint64_t *vtb_binding_064;
	const uint32_t *vtb_binding_065;
	uint64_t vtb_binding_066, vtb_binding_067, vtb_binding_068, vtb_binding_069[32] = { 0 };
	bool vtb_binding_070 = false;
	
	vtb_binding_065 = (const uint32_t *)((uintptr_t)vtb_binding_055 + (vtb_binding_057 - vtb_binding_058));
	for(vtb_binding_066 = 0; vtb_binding_066 < (vtb_binding_062 - vtb_binding_057) / sizeof(*vtb_binding_065); ++vtb_binding_066) {
		if(VTB_RULE_08(vtb_binding_065[vtb_binding_066])) {
			vtb_binding_068 = vtb_binding_057 + (vtb_binding_066 * sizeof(*vtb_binding_065)) + VTB_RULE_09(vtb_binding_065[vtb_binding_066]);
			vtb_binding_070 = (vtb_binding_068 == vtb_binding_063);
		} else if(VTB_RULE_10(vtb_binding_065[vtb_binding_066])) {
			vtb_binding_069[VTB_RULE_05(vtb_binding_065[vtb_binding_066])] = VTB_RULE_12(vtb_binding_057 + (vtb_binding_066 * sizeof(*vtb_binding_065))) + VTB_RULE_11(vtb_binding_065[vtb_binding_066]);
		} else if(VTB_RULE_13(vtb_binding_065[vtb_binding_066])) {
			vtb_binding_069[VTB_RULE_05(vtb_binding_065[vtb_binding_066])] = vtb_binding_069[VTB_RULE_07(vtb_binding_065[vtb_binding_066])] + VTB_RULE_14(vtb_binding_065[vtb_binding_066]);
		} else if(VTB_RULE_16(vtb_binding_065[vtb_binding_066])) {
			vtb_binding_069[VTB_RULE_05(vtb_binding_065[vtb_binding_066])] = vtb_binding_069[VTB_RULE_06(vtb_binding_065[vtb_binding_066])];
		} else if(vtb_binding_070 && VTB_RULE_15(vtb_binding_065[vtb_binding_066])) {
			if(VTB_RULE_03(vtb_binding_069[1], vtb_binding_059, vtb_binding_060)) {
				printf("Name: %s, metaclass: 0x%016" PRIx64, (const char *)((uintptr_t)vtb_binding_055 + (vtb_binding_069[1] - vtb_binding_058)), vtb_binding_069[VTB_RULE_05(vtb_binding_065[vtb_binding_066])]);
				vtb_binding_067 = vtb_binding_069[VTB_RULE_05(vtb_binding_065[vtb_binding_066])] - vtb_binding_058;
				if((vtb_binding_067 + sizeof(uint64_t)) <= vtb_binding_056) {
					vtb_binding_064 = (const uint64_t *)((uintptr_t)vtb_binding_055 + vtb_binding_067);
					vtb_binding_068 = VTB_RULE_04(vtb_binding_064[VTB_RULE_02]);
					if(VTB_RULE_03(vtb_binding_068, vtb_binding_061, vtb_binding_062)) {
						vtb_inspect_allocation(vtb_binding_055, vtb_binding_068, vtb_binding_058, vtb_binding_062);
					}
				}
				putchar('\n');
			}
			vtb_binding_070 = false;
		} else if(VTB_RULE_22(vtb_binding_065[vtb_binding_066])) {
			break;
		}
	}
}
