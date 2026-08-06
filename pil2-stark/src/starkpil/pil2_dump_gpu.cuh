#pragma once
// GPU counterpart of pil2_dump.hpp (PIL2_DUMP_DIR): genProof_gpu's stage
// buffers live in device memory, so each dump is a synchronous D2H staging
// copy on the prove's own stream followed by the host .npy writer. Capture
// mode only — genProof_gpu disables its CUDA-graph cache when the env is set
// so no dump can land inside a graph capture — and every hook is a no-op
// (single getenv) when the env is absent.
//
// Differences from the CPU dump set, by construction of the GPU flow:
// per-stage roots and the transcript absorb log are not dumped (roots ride
// the flat `proof` section written from the host-pinned buffer after
// setProof; transcript replay reconstructs from global_challenge +
// challenges + fri betas).
#include <cstring>
#include <vector>

#include "pil2_dump.hpp"

// PIL2_DUMP_ONLY / PIL2_DUMP_SKIP: optional dump-name substring filters
// (keep-if-match / drop-if-match; SKIP wins). A GPU prove's raw dump set is
// dominated by per-instance extended sections (a small guest already produces
// ~22 GB across its instances), so a block-scale capture targets one air with
// PIL2_DUMP_ONLY=ag0_air0_, or everything BUT an already-captured air with
// PIL2_DUMP_SKIP=ag0_air0_.
inline bool pil2DumpWants(const std::string& name) {
    if (!std::getenv("PIL2_DUMP_DIR")) return false;
    const char* skip = std::getenv("PIL2_DUMP_SKIP");
    if (skip && name.find(skip) != std::string::npos) return false;
    const char* only = std::getenv("PIL2_DUMP_ONLY");
    return !only || name.find(only) != std::string::npos;
}

inline void pil2DumpU64Gpu(const std::string& name, const void* d_data,
                           size_t count, cudaStream_t stream) {
    if (!pil2DumpWants(name) || count == 0) return;
    std::vector<uint64_t> h(count);
    CHECKCUDAERR(cudaMemcpyAsync(h.data(), d_data, count * sizeof(uint64_t),
                                 cudaMemcpyDeviceToHost, stream));
    CHECKCUDAERR(cudaStreamSynchronize(stream));
    pil2DumpU64(name, h.data(), count);
}
