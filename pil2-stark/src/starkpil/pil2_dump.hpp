#pragma once
// PIL2_DUMP_DIR: when set, genProof writes stage buffers as NumPy `.npy`
// (v1.0 header + LE u64 data) — self-describing, so consumers `np.load`
// without dtype/length conventions. The ZisK analog of SP1's
// SP1_DUMP_PHASES, consumed by zisk-zorch's verify_* runnables
// (fractalyze/zisk-zorch#59).
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

inline void pil2DumpU64(const std::string& name, const void* data, size_t count) {
    const char* dir = std::getenv("PIL2_DUMP_DIR");
    if (!dir) return;
    std::string p = std::string(dir) + "/" + name + ".npy";
    FILE* f = fopen(p.c_str(), "wb");
    if (!f) { fprintf(stderr, "pil2_dump: cannot open %s\n", p.c_str()); return; }
    // .npy v1.0: 8-byte magic+version, u16 LE header length, then the header
    // dict padded with spaces so the data starts 64-byte aligned.
    std::string hdr = "{'descr': '<u8', 'fortran_order': False, 'shape': (" +
                      std::to_string(count) + ",), }";
    size_t total = 10 + hdr.size() + 1;
    hdr.append((64 - (total % 64)) % 64, ' ');
    hdr.push_back('\n');
    uint16_t hlen = static_cast<uint16_t>(hdr.size());
    fwrite("\x93NUMPY\x01\x00", 1, 8, f);
    fwrite(&hlen, sizeof(hlen), 1, f);
    fwrite(hdr.data(), 1, hdr.size(), f);
    fwrite(data, sizeof(uint64_t), count, f);
    fclose(f);
}
