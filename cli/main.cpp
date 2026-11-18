// Standalone check that the portable node library links.
// The desktop serve process and the phone glue stay on the host.

#include "pm/server/vfs.hpp"

#include <CLI/CLI.hpp>

#include <iostream>

int main(int argc, char** argv)
{
    CLI::App app{"pm-server"};
    app.require_subcommand(0, 1);
    auto* version = app.add_subcommand("version", "Print the library role");
    CLI11_PARSE(app, argc, argv);
    if (version->parsed() || argc < 2) {
        std::cout << "{\"ok\":true,\"role\":\"server\"}\n";
        return 0;
    }
    std::cerr << "{\"ok\":false,\"error\":\"unknown command\"}\n";
    return 2;
}
