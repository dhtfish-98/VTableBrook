#include "vtb_image_layout.h"

int
main(int vtb_binding_083, char **vtb_binding_084) {
	if(vtb_binding_083 != 2) {
		printf("Usage: %s kernel\n", vtb_binding_084[0]);
	} else {
		int vtb_binding_085 = open(vtb_binding_084[1], O_RDONLY);
		size_t vtb_binding_086 = (size_t)lseek(vtb_binding_085, 0, SEEK_END);
		struct mach_header_64 *vtb_binding_087 = mmap(NULL, vtb_binding_086, PROT_READ, MAP_PRIVATE, vtb_binding_085, 0);
		close(vtb_binding_085);
		if(vtb_binding_087 != MAP_FAILED) {
			if(vtb_binding_087->magic == MH_MAGIC_64 &&
			   vtb_binding_087->cputype == CPU_TYPE_ARM64)
			{
				vtb_review_image(vtb_binding_087, vtb_binding_086);
			}
			munmap(vtb_binding_087, vtb_binding_086);
		}
	}
}
