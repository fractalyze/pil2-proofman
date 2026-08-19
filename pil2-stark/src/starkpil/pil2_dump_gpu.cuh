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
// (keep-if-any-match / drop-if-any-match; SKIP wins), each a comma-separated
// list. A GPU prove's raw dump set is dominated by per-instance extended
// sections (a small guest already produces ~22 GB across its instances), so
// a block-scale capture targets one air with PIL2_DUMP_ONLY=ag0_air0_, or
// everything BUT an already-captured air with PIL2_DUMP_SKIP=ag0_air0_.
// PIL2_DUMP_SECTIONS: comma-separated section-name suffixes to keep (e.g.
// "trace_post,publics,proof"); a name that is a bare instance prefix (ends
// in '_') passes this filter so the per-instance meta.json still lands. The
// lean witness capture for zisk-zorch's replay is
//   PIL2_DUMP_SECTIONS=trace_post,publics,global_challenge,airvalues,
//                      airgroupvalues,proofvalues,challenges,evals,proof
inline bool pil2DumpMatchesAny(const char* list, const std::string& name) {
    if (!list) return false;
    std::string s(list);
    size_t start = 0;
    while (start <= s.size()) {
        size_t end = s.find(',', start);
        if (end == std::string::npos) end = s.size();
        std::string tok = s.substr(start, end - start);
        if (!tok.empty() && name.find(tok) != std::string::npos) return true;
        start = end + 1;
    }
    return false;
}

inline bool pil2DumpWants(const std::string& name) {
    if (!std::getenv("PIL2_DUMP_DIR")) return false;
    if (pil2DumpMatchesAny(std::getenv("PIL2_DUMP_SKIP"), name)) return false;
    const char* only = std::getenv("PIL2_DUMP_ONLY");
    if (only && !pil2DumpMatchesAny(only, name)) return false;
    const char* sections = std::getenv("PIL2_DUMP_SECTIONS");
    if (sections && !name.empty() && name.back() != '_') {
        // section suffix = everything after the last '_' of the instance
        // prefix; match the listed names as suffixes of the dump name.
        std::string s(sections);
        size_t start = 0;
        bool hit = false;
        while (start <= s.size() && !hit) {
            size_t end = s.find(',', start);
            if (end == std::string::npos) end = s.size();
            std::string tok = s.substr(start, end - start);
            if (!tok.empty() && name.size() >= tok.size() + 1 &&
                name.compare(name.size() - tok.size(), tok.size(), tok) == 0 &&
                name[name.size() - tok.size() - 1] == '_')
                hit = true;
            start = end + 1;
        }
        if (!hit) return false;
    }
    return true;
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
