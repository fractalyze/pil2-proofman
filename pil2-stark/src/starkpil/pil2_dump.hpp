#pragma once
// PIL2_DUMP_DIR: when set, genProof writes stage buffers as raw LE u64
// (<name>.bin) — the ZisK analog of SP1's SP1_DUMP_PHASES, consumed by
// zisk-zorch's verify_* runnables (fractalyze/zisk-zorch#59).
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

inline void pil2DumpU64(const std::string& name, const void* data, size_t count) {
    const char* dir = std::getenv("PIL2_DUMP_DIR");
    if (!dir) return;
    std::string p = std::string(dir) + "/" + name + ".bin";
    FILE* f = fopen(p.c_str(), "wb");
    if (!f) { fprintf(stderr, "pil2_dump: cannot open %s\n", p.c_str()); return; }
    fwrite(data, sizeof(uint64_t), count, f);
    fclose(f);
}
