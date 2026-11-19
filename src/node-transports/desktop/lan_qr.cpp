#include "lan/tanit_lan_qr.hpp"
#include "fs/path_sanitizer.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace media_cli::lan {
namespace {

std::uint8_t rs_mul(std::uint8_t x, std::uint8_t y)
{
    int z = 0;
    for (int i = 7; i >= 0; --i) {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= ((y >> i) & 1) * static_cast<int>(x);
    }
    return static_cast<std::uint8_t>(z);
}

std::vector<std::uint8_t> rs_divisor(int degree)
{
    std::vector<std::uint8_t> result(static_cast<size_t>(degree));
    result.back() = 1;
    std::uint8_t root = 1;
    for (int i = 0; i < degree; ++i) {
        for (size_t j = 0; j < result.size(); ++j) {
            result[j] = rs_mul(result[j], root);
            if (j + 1 < result.size())
                result[j] ^= result[j + 1];
        }
        root = rs_mul(root, 0x02);
    }
    return result;
}

std::vector<std::uint8_t> rs_remainder(const std::vector<std::uint8_t>& data,
                                       const std::vector<std::uint8_t>& divisor)
{
    std::vector<std::uint8_t> result(divisor.size());
    for (std::uint8_t b : data) {
        const std::uint8_t factor = static_cast<std::uint8_t>(b ^ result[0]);
        result.erase(result.begin());
        result.push_back(0);
        for (size_t j = 0; j < result.size(); ++j)
            result[j] ^= rs_mul(divisor[j], factor);
    }
    return result;
}

struct Version {
    int n1;
    int data1;
    int ecc1;
    int n2;
    int data2;
    int ecc2;
};

// ECC M only. data/ecc are per block; n2 is the longer group when the version splits.
constexpr Version k_versions[] = {
    {},
    {1, 16, 10, 0, 0, 0},
    {1, 28, 16, 0, 0, 0},
    {1, 44, 26, 0, 0, 0},
    {2, 32, 18, 0, 0, 0},
    {2, 43, 24, 0, 0, 0},
    {4, 27, 16, 0, 0, 0},
    {4, 31, 18, 0, 0, 0},
    {2, 38, 22, 2, 39, 22},
    {3, 36, 22, 2, 37, 22},
    {4, 43, 26, 1, 44, 26},
    {1, 50, 30, 4, 51, 30},
    {6, 36, 22, 2, 37, 22},
};

// First entry is the count. Position 6 is included; finder corners are skipped later.
constexpr int k_align[13][4] = {
    {0},
    {0},
    {2, 6, 18},
    {2, 6, 22},
    {2, 6, 26},
    {2, 6, 30},
    {2, 6, 34},
    {3, 6, 22, 38},
    {3, 6, 24, 42},
    {3, 6, 26, 46},
    {3, 6, 28, 50},
    {3, 6, 30, 54},
    {3, 6, 32, 58},
};

constexpr int k_remainder_bits[13] = {0, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0};

int raw_data_modules(int ver)
{
    int result = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
        const int num_align = ver / 7 + 2;
        result -= (25 * num_align - 10) * num_align - 55;
        if (ver >= 7)
            result -= 36;
    }
    return result;
}

int format_bits(int mask)
{
    // ECC M is 00, so the 5-bit value is the mask. BCH generator 0x537, then XOR 0x5412.
    int rem = mask;
    for (int i = 0; i < 10; ++i)
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    return ((mask << 10) | rem) ^ 0x5412;
}

int version_bits(int ver)
{
    int rem = ver;
    for (int i = 0; i < 12; ++i)
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    return (ver << 12) | rem;
}

bool mask_on(int mask, int y, int x)
{
    switch (mask) {
    case 0: return ((y + x) & 1) == 0;
    case 1: return (y & 1) == 0;
    case 2: return x % 3 == 0;
    case 3: return (y + x) % 3 == 0;
    case 4: return (((y / 2) + (x / 3)) & 1) == 0;
    case 5: return (y * x) % 2 + (y * x) % 3 == 0;
    case 6: return (((y * x) % 2 + (y * x) % 3) & 1) == 0;
    default: return (((y + x) % 2 + (y * x) % 3) & 1) == 0;
    }
}

struct Grid {
    int size = 0;
    std::vector<std::uint8_t> modules;
    std::vector<std::uint8_t> function;

    explicit Grid(int n) : size(n), modules(static_cast<size_t>(n * n)), function(modules.size()) {}

    void set_function(int x, int y, bool dark)
    {
        if (x < 0 || y < 0 || x >= size || y >= size)
            return;
        const size_t i = static_cast<size_t>(y * size + x);
        modules[i]      = dark ? 1 : 0;
        function[i]     = 1;
    }

    void set_color(int x, int y, bool dark)
    {
        if (x < 0 || y < 0 || x >= size || y >= size)
            return;
        modules[static_cast<size_t>(y * size + x)] = dark ? 1 : 0;
    }

    bool is_function(int x, int y) const
    {
        return function[static_cast<size_t>(y * size + x)] != 0;
    }

    bool dark_at(int x, int y) const
    {
        return modules[static_cast<size_t>(y * size + x)] != 0;
    }
};

void draw_finder(Grid& g, int cx, int cy)
{
    for (int dy = -4; dy <= 4; ++dy) {
        for (int dx = -4; dx <= 4; ++dx) {
            const int dist = std::max(std::abs(dx), std::abs(dy));
            g.set_function(cx + dx, cy + dy, dist != 2 && dist != 4);
        }
    }
}

void draw_alignment(Grid& g, int cx, int cy)
{
    for (int dy = -2; dy <= 2; ++dy) {
        for (int dx = -2; dx <= 2; ++dx) {
            const int dist = std::max(std::abs(dx), std::abs(dy));
            g.set_function(cx + dx, cy + dy, dist != 1);
        }
    }
}

void paint_format(Grid& g, int bits, bool mark)
{
    auto bit = [&](int i) { return ((bits >> i) & 1) != 0; };
    auto put = [&](int x, int y, bool dark) {
        if (mark)
            g.set_function(x, y, dark);
        else
            g.set_color(x, y, dark);
    };
    for (int i = 0; i <= 5; ++i)
        put(8, i, bit(i));
    put(8, 7, bit(6));
    put(8, 8, bit(7));
    put(7, 8, bit(8));
    for (int i = 9; i < 15; ++i)
        put(14 - i, 8, bit(i));
    for (int i = 0; i < 8; ++i)
        put(g.size - 1 - i, 8, bit(i));
    for (int i = 8; i < 15; ++i)
        put(8, g.size - 15 + i, bit(i));
    put(8, g.size - 8, true);
}

void paint_version(Grid& g, int ver)
{
    const int bits = version_bits(ver);
    for (int i = 0; i < 18; ++i) {
        const bool bit = ((bits >> i) & 1) != 0;
        const int a = g.size - 11 + i % 3;
        const int b = i / 3;
        g.set_function(a, b, bit);
        g.set_function(b, a, bit);
    }
}

int penalty(const Grid& g)
{
    const int n = g.size;
    int score = 0;
    auto at = [&](int x, int y) { return g.dark_at(x, y); };

    for (int y = 0; y < n; ++y) {
        int run = 1;
        for (int x = 1; x < n; ++x) {
            if (at(x, y) == at(x - 1, y)) {
                ++run;
            } else {
                if (run >= 5)
                    score += 3 + (run - 5);
                run = 1;
            }
        }
        if (run >= 5)
            score += 3 + (run - 5);
    }
    for (int x = 0; x < n; ++x) {
        int run = 1;
        for (int y = 1; y < n; ++y) {
            if (at(x, y) == at(x, y - 1)) {
                ++run;
            } else {
                if (run >= 5)
                    score += 3 + (run - 5);
                run = 1;
            }
        }
        if (run >= 5)
            score += 3 + (run - 5);
    }
    for (int y = 0; y < n - 1; ++y) {
        for (int x = 0; x < n - 1; ++x) {
            const bool v = at(x, y);
            if (v == at(x + 1, y) && v == at(x, y + 1) && v == at(x + 1, y + 1))
                score += 3;
        }
    }
    auto finder_like = [&](auto dark) {
        for (int i = 0; i + 6 < n; ++i) {
            if (!(dark(i) && !dark(i + 1) && dark(i + 2) && dark(i + 3) && dark(i + 4) && !dark(i + 5)
                  && dark(i + 6)))
                continue;
            const bool left = i >= 4 && !dark(i - 1) && !dark(i - 2) && !dark(i - 3) && !dark(i - 4);
            const bool right =
                i + 10 < n && !dark(i + 7) && !dark(i + 8) && !dark(i + 9) && !dark(i + 10);
            if (left || right)
                score += 40;
        }
    };
    for (int y = 0; y < n; ++y)
        finder_like([&](int x) { return at(x, y); });
    for (int x = 0; x < n; ++x)
        finder_like([&](int y) { return at(x, y); });

    int dark = 0;
    for (std::uint8_t m : g.modules)
        dark += m ? 1 : 0;
    const int percent = dark * 100 / (n * n);
    const int k = std::abs(percent - 50) / 5;
    score += k * 10;
    return score;
}

void append_bits(std::vector<bool>& bits, unsigned value, int count)
{
    for (int i = count - 1; i >= 0; --i)
        bits.push_back(((value >> i) & 1) != 0);
}

} // namespace

bool encode_qr(std::string_view text, std::vector<std::uint8_t>& modules, int& size, std::string& err)
{
    modules.clear();
    size = 0;
    err.clear();
    if (text.size() > 200) {
        err = "QR payload is too long";
        return false;
    }

    int chosen = 0;
    for (int ver = 1; ver <= 12; ++ver) {
        const int count_bits = ver <= 9 ? 8 : 16;
        const Version& v = k_versions[ver];
        const int data_cw = v.n1 * v.data1 + v.n2 * v.data2;
        const int needed = 4 + count_bits + static_cast<int>(text.size()) * 8;
        if (needed <= data_cw * 8) {
            chosen = ver;
            break;
        }
    }
    if (chosen == 0) {
        err = "QR payload is too long";
        return false;
    }

    const Version& ver = k_versions[chosen];
    const int data_cw = ver.n1 * ver.data1 + ver.n2 * ver.data2;
    const int ecc_len = ver.ecc1;
    if (ver.n2 > 0 && ver.ecc2 != ver.ecc1) {
        err = "QR ecc table is inconsistent";
        return false;
    }
    const int total_cw = ver.n1 * (ver.data1 + ver.ecc1) + ver.n2 * (ver.data2 + ver.ecc2);
    const int raw = raw_data_modules(chosen);
    if (total_cw != raw / 8 || (raw % 8) != k_remainder_bits[chosen]) {
        err = "QR version tables do not match the module count";
        return false;
    }

    const int count_bits = chosen <= 9 ? 8 : 16;
    std::vector<bool> bits;
    bits.reserve(static_cast<size_t>(data_cw * 8));
    append_bits(bits, 0x4, 4);
    append_bits(bits, static_cast<unsigned>(text.size()), count_bits);
    for (unsigned char c : text)
        append_bits(bits, c, 8);
    const int capacity_bits = data_cw * 8;
    const int term = std::min(4, capacity_bits - static_cast<int>(bits.size()));
    if (term > 0)
        append_bits(bits, 0, term);
    while ((bits.size() % 8) != 0 && static_cast<int>(bits.size()) < capacity_bits)
        bits.push_back(false);
    std::vector<std::uint8_t> data;
    data.reserve(static_cast<size_t>(data_cw));
    for (size_t i = 0; i < bits.size(); i += 8) {
        std::uint8_t b = 0;
        for (int k = 0; k < 8; ++k)
            b = static_cast<std::uint8_t>((b << 1) | (bits[i + static_cast<size_t>(k)] ? 1 : 0));
        data.push_back(b);
    }
    for (std::uint8_t pad = 0xEC; static_cast<int>(data.size()) < data_cw; pad ^= 0xFD)
        data.push_back(pad);

    struct Block {
        std::vector<std::uint8_t> data;
        std::vector<std::uint8_t> ecc;
    };
    std::vector<Block> blocks;
    const auto divisor = rs_divisor(ecc_len);
    size_t off = 0;
    auto take = [&](int n, int len) {
        for (int i = 0; i < n; ++i) {
            Block b;
            b.data.assign(data.begin() + static_cast<std::ptrdiff_t>(off),
                          data.begin() + static_cast<std::ptrdiff_t>(off + static_cast<size_t>(len)));
            off += static_cast<size_t>(len);
            b.ecc = rs_remainder(b.data, divisor);
            blocks.push_back(std::move(b));
        }
    };
    take(ver.n1, ver.data1);
    take(ver.n2, ver.data2);
    if (off != data.size()) {
        err = "QR block split did not consume the data";
        return false;
    }

    std::vector<std::uint8_t> codewords;
    codewords.reserve(static_cast<size_t>(total_cw));
    const int max_data = ver.n2 > 0 ? ver.data2 : ver.data1;
    for (int i = 0; i < max_data; ++i) {
        for (const auto& b : blocks) {
            if (i < static_cast<int>(b.data.size()))
                codewords.push_back(b.data[static_cast<size_t>(i)]);
        }
    }
    for (int i = 0; i < ecc_len; ++i) {
        for (const auto& b : blocks)
            codewords.push_back(b.ecc[static_cast<size_t>(i)]);
    }
    if (static_cast<int>(codewords.size()) != total_cw) {
        err = "QR interleave length is wrong";
        return false;
    }

    const int n = 21 + (chosen - 1) * 4;
    Grid g(n);
    draw_finder(g, 3, 3);
    draw_finder(g, n - 4, 3);
    draw_finder(g, 3, n - 4);
    const int align_n = k_align[chosen][0];
    for (int i = 0; i < align_n; ++i) {
        for (int j = 0; j < align_n; ++j) {
            if ((i == 0 && j == 0) || (i == 0 && j == align_n - 1) || (i == align_n - 1 && j == 0))
                continue;
            draw_alignment(g, k_align[chosen][1 + i], k_align[chosen][1 + j]);
        }
    }
    for (int i = 0; i < n; ++i) {
        if (!g.is_function(6, i))
            g.set_function(6, i, (i % 2) == 0);
        if (!g.is_function(i, 6))
            g.set_function(i, 6, (i % 2) == 0);
    }
    paint_format(g, format_bits(0), true);
    if (chosen >= 7)
        paint_version(g, chosen);

    int function_count = 0;
    for (std::uint8_t f : g.function)
        function_count += f ? 1 : 0;
    if (n * n - function_count != raw) {
        err = "QR function-module count does not match version " + std::to_string(chosen);
        return false;
    }

    int bit_index = 0;
    const int total_bits = static_cast<int>(codewords.size()) * 8;
    for (int right = n - 1; right >= 1; right -= 2) {
        if (right == 6)
            right = 5;
        for (int vert = 0; vert < n; ++vert) {
            for (int j = 0; j < 2; ++j) {
                const int x = right - j;
                const bool upward = ((right + 1) & 2) == 0;
                const int y = upward ? n - 1 - vert : vert;
                if (x < 0 || y < 0 || x >= n || y >= n)
                    continue;
                if (!g.is_function(x, y) && bit_index < total_bits) {
                    const int shift = 7 - (bit_index & 7);
                    const bool bit =
                        ((codewords[static_cast<size_t>(bit_index >> 3)] >> shift) & 1) != 0;
                    g.set_color(x, y, bit);
                    ++bit_index;
                }
            }
        }
    }
    if (bit_index != total_bits) {
        err = "QR codewords were not placed";
        return false;
    }

    int best_score = 0;
    int best_mask = 0;
    std::vector<std::uint8_t> best;
    for (int mask = 0; mask < 8; ++mask) {
        Grid trial = g;
        for (int y = 0; y < n; ++y) {
            for (int x = 0; x < n; ++x) {
                if (!trial.is_function(x, y) && mask_on(mask, y, x)) {
                    auto& cell = trial.modules[static_cast<size_t>(y * n + x)];
                    cell = static_cast<std::uint8_t>(cell ^ 1);
                }
            }
        }
        paint_format(trial, format_bits(mask), false);
        const int score = penalty(trial);
        if (mask == 0 || score < best_score) {
            best_score = score;
            best_mask = mask;
            best = trial.modules;
        }
    }
    (void)best_mask;
    modules = std::move(best);
    size = n;
    return true;
}

std::string qr_ascii(const std::uint8_t* modules, int size)
{
    if (!modules || size <= 0)
        return {};
    constexpr int k_quiet = 4;
    std::string out;
    const int span = size + k_quiet * 2;
    out.reserve(static_cast<size_t>(span * (span * 2 + 1)));
    for (int y = -k_quiet; y < size + k_quiet; ++y) {
        for (int x = -k_quiet; x < size + k_quiet; ++x) {
            const bool dark = x >= 0 && y >= 0 && x < size && y < size
                              && modules[static_cast<size_t>(y * size + x)] != 0;
            out += dark ? "██" : "  ";
        }
        out.push_back('\n');
    }
    return out;
}

bool write_qr_bmp(const std::filesystem::path& path, const std::uint8_t* modules, int size,
                  int scale, int border, std::string& err)
{
    err.clear();
    if (!modules || size <= 0 || scale < 1 || border < 0) {
        err = "bad QR bitmap";
        return false;
    }
    const int dim = (size + border * 2) * scale;
    const int row_stride = (dim * 3 + 3) & ~3;
    const std::uint32_t pixels = static_cast<std::uint32_t>(row_stride) * static_cast<std::uint32_t>(dim);
    std::vector<std::uint8_t> file(54u + pixels, 0);
    auto put16 = [&](size_t at, unsigned v) {
        file[at] = static_cast<std::uint8_t>(v & 0xFF);
        file[at + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
    };
    auto put32 = [&](size_t at, unsigned v) {
        put16(at, v & 0xFFFF);
        put16(at + 2, (v >> 16) & 0xFFFF);
    };
    file[0] = 'B';
    file[1] = 'M';
    put32(2, static_cast<unsigned>(file.size()));
    put32(10, 54);
    put32(14, 40);
    put32(18, static_cast<unsigned>(dim));
    put32(22, static_cast<unsigned>(dim));
    put16(26, 1);
    put16(28, 24);
    put32(34, pixels);

    for (int y = 0; y < dim; ++y) {
        // BMP rows are bottom-up.
        const int src_y = dim - 1 - y;
        std::uint8_t* row = file.data() + 54 + static_cast<size_t>(y) * static_cast<size_t>(row_stride);
        for (int x = 0; x < dim; ++x) {
            const int mx = x / scale - border;
            const int my = src_y / scale - border;
            const bool dark = mx >= 0 && my >= 0 && mx < size && my < size
                              && modules[static_cast<size_t>(my * size + mx)] != 0;
            const std::uint8_t c = dark ? 0 : 255;
            row[x * 3] = c;
            row[x * 3 + 1] = c;
            row[x * 3 + 2] = c;
        }
    }

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        err = "could not write QR image";
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    if (!ofs) {
        err = "could not write QR image";
        return false;
    }
    return true;
}

} // namespace media_cli::lan

#ifdef TANIT_LAN_QR_TEST
#include <iostream>
int main()
{
    std::vector<std::uint8_t> modules;
    int size = 0;
    std::string err;
    if (!media_cli::lan::encode_qr("HELLO WORLD", modules, size, err)) {
        std::cerr << err << "\n";
        return 1;
    }
    if (size != 21) {
        std::cerr << "HELLO WORLD should be version 1 (21), got " << size << "\n";
        return 1;
    }
    std::cout << "size " << size << "\n";
    const auto hello = modules;
    const int hello_size = size;
    std::cout << media_cli::lan::qr_ascii(hello.data(), hello_size);
    const std::filesystem::path bmp = "tanit-qr-test.bmp";
    if (!media_cli::lan::write_qr_bmp(bmp, hello.data(), hello_size, 8, 4, err)) {
        std::cerr << err << "\n";
        return 1;
    }
    std::cout << "bmp " << media::path::path_to_utf8(bmp) << "\n";
    const std::string uri =
        "tanit://pair?v=1&host=192.168.1.20&port=8091&fp="
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "&secret=tp1_abcdefghijklmnopqrstuv&name=Desk";
    if (!media_cli::lan::encode_qr(uri, modules, size, err)) {
        std::cerr << "uri: " << err << "\n";
        return 1;
    }
    std::cout << "uri size " << size << " bytes " << uri.size() << "\n";
    if (!media_cli::lan::encode_qr(std::string(200, 'A'), modules, size, err)) {
        std::cerr << "200: " << err << "\n";
        return 1;
    }
    if (media_cli::lan::encode_qr(std::string(201, 'A'), modules, size, err)) {
        std::cerr << "201 should not fit\n";
        return 1;
    }
    std::cout << "limits ok\n";
    return 0;
}
#endif
