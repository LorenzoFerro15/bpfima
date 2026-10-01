#ifndef BPFIMA_TEST_KFUNC_ABI_H
#define BPFIMA_TEST_KFUNC_ABI_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "../../include/bpfima_kfunc_types.h"

/* Check the loaded module before any fixture can call an older, unsafe ABI. */
static int bpfima_test_check_kfunc_abi(void)
{
    const struct
    {
        const char *name;
        unsigned int count;
        const char *arguments[4];
    } functions[] = {
        {"bpfima_measurement_extend", 2, {"data", "data__sz"}},
        {"bpfima_tpm_get_pcr_value", 2, {"pcr_buf", "pcr_buf__sz"}},
        {"bpfima_tpm_is_available", 0, {NULL}},
        {"bpfima_container_get_or_create", 2, {"container_id", "container_id__sz"}},
        {"bpfima_container_get_count", 0, {NULL}},
        {"bpfima_container_get_measurement_count", 2, {"container_id", "container_id__sz"}},
        {"bpfima_container_exists", 2, {"container_id", "container_id__sz"}},
        {"bpfima_container_get_leaf_hash", 4, {"container_id", "container_id__sz", "leaf_hash", "leaf_hash__sz"}},
        {"bpfima_merkle_get_root", 2, {"root_hash", "root_hash__sz"}},
        {"bpfima_policy_update_filter_flags", 3, {"namespace_id", "namespace_id__sz", "new_flags"}},
        {"bpfima_policy_update_action_flags", 3, {"namespace_id", "namespace_id__sz", "new_flags"}},
        {"bpfima_policy_update_min_file_size", 3, {"namespace_id", "namespace_id__sz", "new_size"}},
        {"bpfima_policy_update_log_level", 3, {"namespace_id", "namespace_id__sz", "new_level"}},
        {"bpfima_policy_get_changes_hash", 4, {"namespace_id", "namespace_id__sz", "hash_out", "hash_out__sz"}},
        {"bpfima_policy_namespace_get_config", 4, {"namespace_id", "namespace_id__sz", "config", "config__sz"}},
        {"bpfima_policy_should_ignore_cgroup", 3, {"cgroup_name__nullable", "cgroup_name__sz", "filter_flags"}},
        {"bpfima_policy_should_ignore_path", 3, {"path__nullable", "path__sz", "filter_flags"}},
    };
    const struct
    {
        const char *name;
        size_t offset;
    } policy_fields[] = {
        {"enabled", offsetof(struct bpfima_policy_config, enabled)},
        {"filter_flags", offsetof(struct bpfima_policy_config, filter_flags)},
        {"action_flags", offsetof(struct bpfima_policy_config, action_flags)},
        {"min_file_size", offsetof(struct bpfima_policy_config, min_file_size)},
        {"max_path_depth", offsetof(struct bpfima_policy_config, max_path_depth)},
        {"log_level", offsetof(struct bpfima_policy_config, log_level)},
        {"merkle_history_max_size", offsetof(struct bpfima_policy_config, merkle_history_max_size)},
        {"merkle_history_scope", offsetof(struct bpfima_policy_config, merkle_history_scope)},
        {"reserved", offsetof(struct bpfima_policy_config, reserved)},
    };
    struct btf *base = btf__load_vmlinux_btf();
    struct btf *module = NULL;
    const struct btf_type *type;
    int id;
    int ret = 1;

    if (!base || libbpf_get_error(base))
    {
        fprintf(stderr, "FAIL: cannot read kernel BTF\n");
        return 1;
    }
    module = btf__load_module_btf("bpfima", base);
    if (!module || libbpf_get_error(module))
    {
        module = NULL;
        fprintf(stderr, "FAIL: cannot read bpfima module BTF\n");
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); i++)
    {
        id = btf__find_by_name_kind(module, functions[i].name, BTF_KIND_FUNC);
        type = id < 0 ? NULL : btf__type_by_id(module, id);
        type = type ? btf__type_by_id(module, type->type) : NULL;
        if (!type || !btf_is_func_proto(type) || btf_vlen(type) != functions[i].count)
        {
            fprintf(stderr, "FAIL: loaded kfunc %s has an incompatible prototype; reload the updated module\n",
                    functions[i].name);
            goto cleanup;
        }
        for (unsigned int j = 0; j < functions[i].count; j++)
        {
            const char *name = btf__name_by_offset(module, btf_params(type)[j].name_off);
            if (!name || strcmp(name, functions[i].arguments[j]))
            {
                fprintf(stderr, "FAIL: %s argument %u lacks expected name/annotation %s\n",
                        functions[i].name, j, functions[i].arguments[j]);
                goto cleanup;
            }
        }
    }
    id = btf__find_by_name_kind(module, "bpfima_policy_config", BTF_KIND_STRUCT);
    type = id < 0 ? NULL : btf__type_by_id(module, id);
    if (!type || type->size != sizeof(struct bpfima_policy_config) ||
        btf_vlen(type) != sizeof(policy_fields) / sizeof(policy_fields[0]))
    {
        fprintf(stderr, "FAIL: loaded policy configuration has an incompatible layout\n");
        goto cleanup;
    }
    for (unsigned int i = 0; i < btf_vlen(type); i++)
    {
        const char *name = btf__name_by_offset(module, btf_members(type)[i].name_off);
        if (!name || strcmp(name, policy_fields[i].name) ||
            btf_member_bit_offset(type, i) != policy_fields[i].offset * 8)
        {
            fprintf(stderr, "FAIL: policy field %s has an incompatible offset\n", policy_fields[i].name);
            goto cleanup;
        }
    }
    puts("PASS: loaded kfunc size annotations and policy ABI match the test suite");
    ret = 0;

cleanup:
    btf__free(module);
    btf__free(base);
    return ret;
}

#endif /* BPFIMA_TEST_KFUNC_ABI_H */
