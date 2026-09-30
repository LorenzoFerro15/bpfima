#ifndef BPFIMA_KFUNC_BUFFER_H
#define BPFIMA_KFUNC_BUFFER_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#endif

#include "bpfima_kfunc_types.h"

/* Copy once so validation and later string operations use the same bytes. */
static inline int bpfima_copy_kfunc_string(char *dest, size_t dest_size,
                                         const char *src, __u32 src_size,
                                         bool allow_empty)
{
    if (!dest || !src || !src_size || src_size > dest_size)
        return -EINVAL;

    memcpy(dest, src, src_size);
    if (!memchr(dest, '\0', src_size))
        return -EINVAL;

    if (!allow_empty && dest[0] == '\0')
        return -EINVAL;

    return 0;
}

static inline int bpfima_validate_namespace(const char *namespace_id)
{
    if (!namespace_id || namespace_id[0] == '\0' ||
        strcmp(namespace_id, ".") == 0 || strcmp(namespace_id, "..") == 0 ||
        strchr(namespace_id, '/'))
        return -EINVAL;

    return 0;
}

/* All arithmetic is bounded by the fixed field sizes before concatenation. */
static inline int bpfima_prepare_measurement(const void *data, __u32 data_size,
                                            struct bpfima_measurement_request *request,
                                            char *concat_data, size_t concat_size,
                                            size_t *total_len)
{
    size_t dependencies_len;
    size_t offset;

    if (!data || data_size != sizeof(*request) || !request ||
        !concat_data || !total_len)
        return -EINVAL;

    memcpy(request, data, sizeof(*request));
    if (!memchr(request->event_name, '\0', sizeof(request->event_name)) ||
        request->event_name[0] == '\0' ||
        !memchr(request->namespace_id, '\0', sizeof(request->namespace_id)) ||
        !memchr(request->dependencies, '\0', sizeof(request->dependencies)) ||
        request->additional_data_len >= sizeof(request->additional_data) ||
        (request->flags & ~BPFIMA_MEASUREMENT_HAS_DEPENDENCIES))
        return -EINVAL;

    if (request->namespace_id[0] != '\0' &&
        bpfima_validate_namespace(request->namespace_id))
        return -EINVAL;

    if (!(request->flags & BPFIMA_MEASUREMENT_HAS_DEPENDENCIES) &&
        request->dependencies[0] != '\0')
        return -EINVAL;

    request->additional_data[request->additional_data_len] = '\0';
    dependencies_len = strlen(request->dependencies);
    offset = request->additional_data_len;
    if (offset > concat_size)
        return -E2BIG;

    memcpy(concat_data, request->additional_data, offset);
    if (offset && (request->flags & BPFIMA_MEASUREMENT_HAS_DEPENDENCIES))
    {
        if (offset == concat_size)
            return -E2BIG;
        concat_data[offset++] = ' ';
    }

    if (dependencies_len > concat_size - offset)
        return -E2BIG;

    memcpy(concat_data + offset, request->dependencies, dependencies_len);
    offset += dependencies_len;
    if (!offset)
        return -EINVAL;

    *total_len = offset;
    return 0;
}

#endif /* BPFIMA_KFUNC_BUFFER_H */
