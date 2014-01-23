include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)

add_executable(scap-open
	test.c)

target_link_libraries(scap-open
	scap)

install(TARGETS scap-open
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
