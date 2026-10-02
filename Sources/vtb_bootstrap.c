#include "vtb_image_layout.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static bool vtb_same_file(const struct stat *before, const struct stat *after) {
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before->st_mtimespec.tv_sec == after->st_mtimespec.tv_sec &&
           before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec &&
           before->st_ctimespec.tv_sec == after->st_ctimespec.tv_sec &&
           before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
}

static unsigned char *vtb_load_file(const char *path, size_t *length) {
    int descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat before, after;
    unsigned char *buffer = NULL, extra;
    size_t consumed = 0;
    ssize_t amount;
    if (descriptor < 0) { fprintf(stderr, "VTableBrook: cannot open input: %s\n", strerror(errno)); return NULL; }
    if (fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0 ||
        (uint64_t)before.st_size > VTB_MAX_FILE_BYTES || (uint64_t)before.st_size > SIZE_MAX) {
        fprintf(stderr, "VTableBrook: input must be a nonempty regular file of at most 1 GiB\n");
        goto finish;
    }
    *length = (size_t)before.st_size;
    buffer = malloc(*length);
    if (!buffer) { fprintf(stderr, "VTableBrook: cannot allocate input buffer\n"); goto finish; }
    while (consumed < *length) {
        amount = read(descriptor, buffer + consumed, *length - consumed);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) goto changed;
        consumed += (size_t)amount;
    }
    do { amount = read(descriptor, &extra, 1); } while (amount < 0 && errno == EINTR);
    if (amount != 0 || fstat(descriptor, &after) != 0 || !vtb_same_file(&before, &after)) goto changed;
    close(descriptor);
    return buffer;
changed:
    fprintf(stderr, "VTableBrook: input changed or could not be completely read\n");
    free(buffer);
    buffer = NULL;
finish:
    close(descriptor);
    return buffer;
}

int main(int argc, char **argv) {
    struct vtb_image image = {0};
    unsigned char *owned;
    bool complete;
    if (argc != 2) { fprintf(stderr, "Usage: %s kernel\n", argv[0]); return 2; }
    owned = vtb_load_file(argv[1], &image.length);
    if (!owned) return 2;
    image.bytes = owned;
    complete = vtb_review_image(&image);
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "VTableBrook: cannot write analysis output\n");
        complete = false;
    }
    if (image.error) fprintf(stderr, "VTableBrook: %s\n", image.error);
    free(owned);
    return complete ? 0 : 2;
}
