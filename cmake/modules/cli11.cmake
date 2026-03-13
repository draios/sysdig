option(USE_BUNDLED_CLI11 "Enable building of the bundled CLI11" ${USE_BUNDLED_DEPS})

if(USE_BUNDLED_CLI11)
    include(FetchContent)
    FetchContent_Declare(cli11
        URL https://github.com/CLIUtils/CLI11/archive/refs/tags/v2.4.1.tar.gz
        URL_HASH SHA256=73b7ec52261ce8fe980a29df6b4ceb66243bb0b779451dbd3d014cfec9fdbb58
    )
    FetchContent_MakeAvailable(cli11)
else()
    find_package(CLI11 CONFIG REQUIRED)
endif()
