# Generation of events data structures for driver and userspace

set(CODE_GENERATOR "${CMAKE_SOURCE_DIR}/scripts/code_generation/generate.lua")
set(INPUT_FILES
    "${CMAKE_SOURCE_DIR}/common/flags.lua"
    "${CMAKE_SOURCE_DIR}/common/events.lua"
)

function(add_generate_command OUTPUT_DIR)
    add_custom_command(
        OUTPUT
            "${OUTPUT_DIR}/event_info.inc"
            "${OUTPUT_DIR}/event_type.inc"
            "${OUTPUT_DIR}/flags.inc"
            "${OUTPUT_DIR}/flags.h"
            "${OUTPUT_DIR}/ppm_events.inc"
            "${OUTPUT_DIR}/syscall_table.inc"
        DEPENDS
            ${LUAJIT_BIN}
            ${CODE_GENERATOR}
            ${INPUT_FILES}
        COMMAND
            ${CMAKE_COMMAND} -E make_directory "${OUTPUT_DIR_1}"
        COMMAND
            ${LUAJIT_BIN} ${CODE_GENERATOR}
            "-o" "${OUTPUT_DIR}"
            "-p" "${CMAKE_SOURCE_DIR}/driver/ppm_events_public.h"
            "--header" "1"
            ${INPUT_FILES}
        WORKING_DIRECTORY
            "${CMAKE_SOURCE_DIR}/scripts/code_generation"
        COMMENT
            "Generating events code in ${OUTPUT_DIR}"
        VERBATIM
    )
endfunction()

set(OUTPUT_DIR_1 "${CMAKE_BINARY_DIR}/generated")
set(OUTPUT_DIR_2 "${CMAKE_SOURCE_DIR}/driver")

add_generate_command(${OUTPUT_DIR_1})
add_generate_command(${OUTPUT_DIR_2})

add_custom_target(generate_event_files
    DEPENDS
        ${INPUT_FILES}
        "${OUTPUT_DIR_1}/event_info.inc"
        "${OUTPUT_DIR_2}/event_info.inc"
    VERBATIM
)
